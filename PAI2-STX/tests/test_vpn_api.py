"""Pruebas del controlador REST, sin abrir ni modificar el servidor real."""
import os
import socket
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.vpn_api.app import app, _manager
from src.vpn_api.openvpn_manager import (
    ClienteVPNNoEncontrado, IdentidadVPNNoCoincide,
    OpenVPNManager, OpenVPNManagerError, VPNConnection, parse_status3,
)

TOKEN = 't' * 48
HEAD = ('HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t'
        'Virtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\t'
        'Connected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher')


def sample(*ids):
    rows = [f'CLIENT_LIST\trf5_inv_001\tudp4:127.0.0.1:65000\t10.8.0.{i+2}\t\t12\t34\t2026-10-16 12:00:00\t1792152000\tUNDEF\t{i}\t{i}\tAES-256-GCM' for i in ids]
    return '\n'.join(['TITLE\tOpenVPN 2.7', HEAD, *rows, 'END'])


@pytest.fixture
def token_file(tmp_path, monkeypatch):
    p = tmp_path / 'token'
    p.write_text(TOKEN)
    monkeypatch.setenv('BYODSEC_VPN_API_TOKEN_FILE', str(p))
    return p


class DummyManager:
    def __init__(self):
        self.active = {7: VPNConnection(7, 'rf5_inv_001', '10.8.0.2', 'udp4:127.0.0.1:65000', 'today', 120, 340),
                       8: VPNConnection(8, 'otro_usuario', '10.8.0.3', 'udp4:127.0.0.1:65001', 'today', 55, 66)}

    def connections(self):
        return list(self.active.values())

    def disconnect(self, cid, cn):
        if cid not in self.active:
            raise ClienteVPNNoEncontrado()
        if self.active[cid].common_name != cn:
            raise IdentidadVPNNoCoincide()
        del self.active[cid]
        return {'status':'disconnected','client_id':cid,'common_name':cn}


@pytest.fixture
def web_client(token_file):
    mgr = DummyManager()
    app.dependency_overrides[_manager] = lambda: mgr
    with TestClient(app) as client:
        yield client, mgr
    app.dependency_overrides.clear()


def headers(key=TOKEN):
    return {'Authorization': f'Bearer {key}'}


def test_parse_status3_cid_y_encabezados():
    parsed = parse_status3(sample(7, 42))
    assert [row.client_id for row in parsed] == [7, 42]
    assert parsed[0].common_name == 'rf5_inv_001'
    assert parsed[0].virtual_address == '10.8.0.9'  # ID 7 -> 9


def test_status_sin_clientes():
    assert parse_status3(sample()) == []


def test_respuesta_sin_cabecera_rechazada():
    with pytest.raises(OpenVPNManagerError):
        parse_status3('TITLE\tOpenVPN\nEND')


def test_sin_token_rechazado(web_client):
    client, _ = web_client
    for method, path in [('get','/api/v1/vpn/status'), ('get','/api/v1/vpn/connections'),
                         ('post','/internal/vpn/disconnect')]:
        result = getattr(client, method)(path)
        assert result.status_code == 401


def test_token_malo_rechazado(web_client):
    client, _ = web_client
    assert client.get('/api/v1/vpn/status',headers=headers('incorrecto')).status_code == 401


def test_get_status_y_connections(web_client):
    client, _ = web_client
    assert client.get('/api/v1/vpn/status',headers=headers()).json()['connected_clients'] == 2
    response = client.get('/api/v1/vpn/connections',headers=headers())
    assert response.status_code == 200
    assert len(response.json()['connections']) == 2


def test_desconexion_exitosa(web_client):
    client, mgr = web_client
    r = client.post('/internal/vpn/disconnect', headers=headers(),
                    json={'client_id':7,'expected_common_name':'rf5_inv_001'})
    assert r.status_code == 200
    assert r.json()['status'] == 'disconnected'
    assert 7 not in mgr.active
    assert 8 in mgr.active


def test_no_puede_cerrar_cliente_ajeno(web_client):
    client, mgr = web_client
    r = client.post('/internal/vpn/disconnect', headers=headers(),
                    json={'client_id':8,'expected_common_name':'rf5_inv_001'})
    assert r.status_code == 409
    assert 8 in mgr.active


def test_clase_cliente_inexistente(web_client):
    client, _ = web_client
    r = client.post('/internal/vpn/disconnect', headers=headers(),
                    json={'client_id':999,'expected_common_name':'rf5_inv_001'})
    assert r.status_code == 404


def test_validacion_impide_valores_inesperados(web_client):
    client, _ = web_client
    for payload in [{'client_id':-1,'expected_common_name':'rf5_inv_001'},
                    {'client_id':7,'expected_common_name':''}]:
        assert client.post('/internal/vpn/disconnect', headers=headers(),json=payload).status_code == 422


def test_servicio_fallo_retorna_503(web_client):
    client, _ = web_client
    class Broken:
        def connections(self):
            raise OpenVPNManagerError('secreto interno')
    app.dependency_overrides[_manager] = lambda: Broken()
    response = client.get('/api/v1/vpn/status',headers=headers())
    assert response.status_code == 503
    assert 'secreto interno' not in response.text


def test_protocolo_real_socket_unix(tmp_path):
    """Socket UNIX simulado: comprueba protocolo real contra un daemon falso."""
    path = tmp_path / 'management.sock'
    ready = threading.Event()
    def serve():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(str(path)); s.listen(1); ready.set()
            conn, _ = s.accept()
            with conn:
                conn.sendall(b'>INFO:OpenVPN Management Interface Version 5\r\n')
                data = conn.recv(1024)
                assert data == b'status 3\n'
                conn.sendall(sample(7).encode() + b'\r\n')
    thread = threading.Thread(target=serve,daemon=True)
    thread.start()
    assert ready.wait(2)
    manager = OpenVPNManager(path,timeout=1)
    assert manager.connections()[0].client_id == 7
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_management_disconnect_usa_cid_y_halt(monkeypatch):
    manager = OpenVPNManager('/tmp/fake-not-used')
    operations = []
    active = {'yes': True}

    def fake_command(command):
        operations.append(command)
        if command == 'status 3':
            return sample(7) if active['yes'] else sample()
        if command == 'client-kill 7 HALT':
            active['yes'] = False
            return 'SUCCESS: client-kill command succeeded'
        raise AssertionError(command)

    monkeypatch.setattr(manager, '_command', fake_command)
    result = manager.disconnect(7, 'rf5_inv_001')
    assert result['status'] == 'disconnected'
    assert operations == ['status 3', 'client-kill 7 HALT', 'status 3']


def test_management_rechaza_cn_incorrecto_antes_de_enviar_kill(monkeypatch):
    manager = OpenVPNManager('/tmp/fake-not-used')
    operations = []

    def fake_command(command):
        operations.append(command)
        return sample(7)

    monkeypatch.setattr(manager, '_command', fake_command)
    with pytest.raises(IdentidadVPNNoCoincide):
        manager.disconnect(7, 'otro_cn')
    assert operations == ['status 3']
