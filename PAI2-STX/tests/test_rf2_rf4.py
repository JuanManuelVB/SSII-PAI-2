"""Pruebas aisladas de autenticación, sesiones y cierre sin modificar RF1/RF5."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient

from pki.scripts import pki
from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.common.seguridad import crear_hash_contrasena
from src.gateway.app import app
from src.rf2.autenticacion import mensaje_a_firmar
from src.rf2.sesiones import _hash_token, validar_sesion
from src.rf4.cierre import revocar_sesion


@pytest.fixture
def escenario(tmp_path, monkeypatch):
    pki.crear_ca(tmp_path)
    pki.emitir_cliente(tmp_path, "device-1")
    pki.emitir_cliente(tmp_path, "device-2")
    ruta_db = tmp_path / "usuarios.sqlite3"
    inicializar_base_datos(ruta_db)
    ruta_ca = tmp_path / "pki/ca/ca.crt"
    certificado = tmp_path / "pki/clients/device-1/device-1.crt"
    clave = tmp_path / "pki/clients/device-1/device-1.key"
    otro_cert = tmp_path / "pki/clients/device-2/device-2.crt"
    otra_clave = tmp_path / "pki/clients/device-2/device-2.key"
    with conectar_base_datos(ruta_db) as conexion:
        conexion.execute("""INSERT INTO users
            (username,password_hash,role,status,origin,created_at,updated_at)
            VALUES (?,?, 'PDI','active','MANUAL','ahora','ahora')""",
            ("pdi_test", crear_hash_contrasena("contrasenaSegura123")),
        )
        for nombre, device_id in [(certificado, "device-1"), (otro_cert, "device-2")]:
            cert = x509.load_pem_x509_certificate(nombre.read_bytes())
            huella = hashlib.sha256(cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            )).hexdigest()
            conexion.execute("""INSERT INTO device_pairings
                (device_id,username,public_key_fingerprint,certificate_serial,certificate_path,created_at,status)
                VALUES (?, 'pdi_test', ?, ?, '', 'ahora', 'active')""",
                (device_id, huella, str(cert.serial_number)),
            )
    monkeypatch.setattr(app.state, "ruta_base_datos", ruta_db, raising=False)
    monkeypatch.setattr(app.state, "ruta_ca", ruta_ca, raising=False)
    monkeypatch.setattr(app.state, "ruta_revocados", tmp_path / "pki/ca/revoked.json", raising=False)
    ruta_auditoria = tmp_path / "auditoria.jsonl"
    monkeypatch.setattr(app.state, "ruta_auditoria_rf4", ruta_auditoria, raising=False)
    return {
        "db": ruta_db, "ca": ruta_ca, "cert": certificado, "key": clave,
        "otro_cert": otro_cert, "otra_clave": otra_clave, "auditoria": ruta_auditoria,
    }




def app_pruebas_mtls(escenario):
    # Solo las pruebas de lógica emulan el dato que realmente inyecta
    # MTLSH11Protocol a partir del socket TLS (no una cabecera de usuario).
    certificado = x509.load_pem_x509_certificate(escenario["cert"].read_bytes())
    der = certificado.public_bytes(serialization.Encoding.DER)

    async def wrapper(scope, receive, send):
        if scope["type"] == "http":
            scope["mtls_client_cert_der"] = der
        await app(scope, receive, send)

    return wrapper

def _peticion_login(client, escenario, *, password="contrasenaSegura123", device_id="device-1", certificado=None, clave=None, nonce=None, firma_invalida=False):
    certificado = certificado or escenario["cert"]
    clave = clave or escenario["key"]
    if nonce is None:
        challenge = client.post("/api/v1/sessions/challenge", json={"username": "pdi_test", "device_id": device_id})
        assert challenge.status_code == 200, challenge.text
        nonce = challenge.json()["nonce"]
    private_key = serialization.load_pem_private_key(clave.read_bytes(), None)
    signature = private_key.sign(
        mensaje_a_firmar(nonce, "pdi_test", device_id), padding.PKCS1v15(), hashes.SHA256(),
    )
    if firma_invalida:
        signature = b"\x01" * 256
    return client.post("/api/v1/sessions/login", json={
        "username": "pdi_test", "password": password, "device_id": device_id,
        "nonce": nonce, "certificate": certificado.read_text(encoding="ascii"),
        "signature": base64.b64encode(signature).decode(),
    })


def test_login_me_logout_rechaza_reutilizacion_y_audita(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        login = _peticion_login(client, escenario)
        assert login.status_code == 200, login.text
        token = login.json()["access_token"]
        assert login.json()["token_type"] == "bearer"
        headers = {"Authorization": "Bearer " + token}
        assert client.get("/api/v1/sessions/me", headers=headers).json()["role"] == "PDI"
        resultado = client.post("/api/v1/sessions/logout", headers=headers)
        assert resultado.status_code == 200
        assert resultado.json()["status"] == "closed"
        assert resultado.headers["connection"] == "close"
        assert client.get("/api/v1/sessions/me", headers=headers).status_code == 401
        assert client.post("/api/v1/sessions/logout", headers=headers).status_code == 401
    with conectar_base_datos(escenario["db"]) as conexion:
        fila = conexion.execute("SELECT token_hash, revoked_at FROM sessions").fetchone()
        assert fila["token_hash"] == _hash_token(token)
        assert token not in fila["token_hash"]
        assert fila["revoked_at"] is not None
    eventos = [json.loads(line) for line in escenario["auditoria"].read_text().splitlines()]
    assert eventos[0]["event"] == "session_closed"
    assert "token" not in eventos[0]


def test_login_rechaza_contrasena_incorrecta(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        assert _peticion_login(client, escenario, password="incorrecta").status_code == 401


def test_login_rechaza_firma_invalida(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        assert _peticion_login(client, escenario, firma_invalida=True).status_code == 401


def test_login_rechaza_certificado_ajeno_al_dispositivo(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        assert _peticion_login(client, escenario, certificado=escenario["otro_cert"], clave=escenario["otra_clave"]).status_code == 401


def test_login_rechaza_reutilizar_desafio(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        challenge = client.post("/api/v1/sessions/challenge", json={"username": "pdi_test", "device_id": "device-1"}).json()
        assert _peticion_login(client, escenario, nonce=challenge["nonce"]).status_code == 200
        assert _peticion_login(client, escenario, nonce=challenge["nonce"]).status_code == 401


def test_bloqueo_usuario_invalida_sesion(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        login = _peticion_login(client, escenario)
        token = login.json()["access_token"]
        with conectar_base_datos(escenario["db"]) as conexion:
            conexion.execute("UPDATE users SET status='blocked' WHERE username='pdi_test'")
        assert client.get("/api/v1/sessions/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_revocacion_dispositivo_invalida_sesion(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        token = _peticion_login(client, escenario).json()["access_token"]
        with conectar_base_datos(escenario["db"]) as conexion:
            conexion.execute("UPDATE device_pairings SET status='revoked' WHERE device_id='device-1'")
        assert client.get("/api/v1/sessions/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_sesion_caducada_no_funciona(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        token = _peticion_login(client, escenario).json()["access_token"]
        with conectar_base_datos(escenario["db"]) as conexion:
            conexion.execute("UPDATE sessions SET expires_at=?", ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),))
        assert client.get("/api/v1/sessions/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
        assert revocar_sesion(token, escenario["db"]) is False


def test_no_se_aceptan_credenciales_por_http(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="http://testserver") as client:
        respuesta = client.post("/api/v1/sessions/challenge", json={"username":"pdi_test","device_id":"device-1"})
        assert respuesta.status_code == 403


def test_sesion_ajena_no_se_cierra(escenario):
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        token_a = _peticion_login(client, escenario).json()["access_token"]
        token_b = _peticion_login(client, escenario).json()["access_token"]
        assert client.post("/api/v1/sessions/logout", headers={"Authorization": "Bearer " + token_a}).status_code == 200
        assert client.get("/api/v1/sessions/me", headers={"Authorization": "Bearer " + token_b}).status_code == 200


def test_certificado_revocado_por_ca_rechazado(escenario):
    certificado = x509.load_pem_x509_certificate(escenario["cert"].read_bytes())
    revocados = escenario["ca"].parent / "revoked.json"
    revocados.write_text(json.dumps([{"serial": str(certificado.serial_number)}]), encoding="utf-8")
    with TestClient(app_pruebas_mtls(escenario), base_url="https://testserver") as client:
        assert _peticion_login(client, escenario).status_code == 401
