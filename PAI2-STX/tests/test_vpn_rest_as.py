"""Pruebas REST con respuestas HTTP simuladas: no necesitan AS instalado."""
import httpx
import pytest
from src.vpn_rest_as.client import AccessServerClient, AccessServerError, ConfigAccessServer


def fabrica(handler):
    config = ConfigAccessServer(url='https://as.test:943', username='admin', password='not-a-real-secret')
    return AccessServerClient(config, httpx.MockTransport(handler))


def test_consulta_status_rest_y_no_usa_management_socket():
    llamadas=[]
    def handler(r):
        llamadas.append((r.method, r.url.path))
        if r.url.path.endswith('/auth/login/userpassword'):
            assert r.method == 'POST'
            assert r.read().find(b'request_admin') >= 0
            return httpx.Response(200, json={'auth_token':'demo'})
        assert r.headers['X-OpenVPN-As-AuthToken'] == 'demo'
        return httpx.Response(200, json={'vpn_clients':[{'username':'rf5_inv_001','client_id':4}, {'username':'otro'}]})
    c=fabrica(handler)
    assert len(c.conexiones_usuario('rf5_inv_001'))==1
    assert llamadas == [('POST','/api/auth/login/userpassword'),('GET','/api/vpn/status')]


def test_desconectar_solo_el_usuario_solicitado():
    def handler(r):
        if r.url.path.endswith('/auth/login/userpassword'):
            return httpx.Response(200, json={'auth_token':'t'})
        assert r.url.path == '/api/vpn/client/disconnect'
        assert r.method == 'POST'
        assert r.read().find(b'rf5_pdi_001') >= 0
        assert r.read().find(b'otro_usuario') == -1
        return httpx.Response(200, json={'result':'OK'})
    assert fabrica(handler).desconectar_usuario('rf5_pdi_001')=={'result':'OK'}


def test_error_admin() -> None:
    c=fabrica(lambda r: httpx.Response(403, json={'error':'Forbidden'}))
    with pytest.raises(AccessServerError, match='403'):
        c.status()


def test_no_acepta_base_http(monkeypatch):
    monkeypatch.setenv('BYODSEC_AS_URL','http://example.org:943')
    monkeypatch.setenv('BYODSEC_AS_ADMIN_USER','admin')
    monkeypatch.setenv('BYODSEC_AS_ADMIN_PASSWORD','pass')
    with pytest.raises(AccessServerError, match='HTTPS'):
        ConfigAccessServer.desde_entorno()


def test_no_acepta_url_con_credenciales(monkeypatch):
    monkeypatch.setenv('BYODSEC_AS_URL','https://root:secret@example.org:943')
    monkeypatch.setenv('BYODSEC_AS_ADMIN_USER','admin')
    monkeypatch.setenv('BYODSEC_AS_ADMIN_PASSWORD','pass')
    with pytest.raises(AccessServerError):
        ConfigAccessServer.desde_entorno()


def test_no_acepta_login_sin_token():
    c=fabrica(lambda r: httpx.Response(200, json={'hello':'world'}))
    with pytest.raises(AccessServerError, match='token'):
        c.status()


def test_username_obligatorio():
    c=fabrica(lambda r: (_ for _ in ()).throw(AssertionError('HTTP no debe llamarse')))
    with pytest.raises(ValueError): c.desconectar_usuario('')


def test_respuesta_status_malformada():
    def handler(r):
        return httpx.Response(200, json={'auth_token':'t'} if r.url.path.endswith('userpassword') else {'vpn_clients':'bad'})
    with pytest.raises(AccessServerError): fabrica(handler).conexiones_usuario('rf5_inv_001')


def test_ruta_estado_vpn_solo_muestra_propias(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from src.rf2.rutas import sesion_autenticada
    from src.vpn_rest_as.rutas import proveedor, router
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[sesion_autenticada] = lambda: {'username':'rf5_inv_001'}
    class Falso:
        def conexiones_usuario(self, username):
            assert username == 'rf5_inv_001'
            return [{'virtual_ipv4_address':'10.8.0.4','datachannel_cipher':'AES-256-GCM'}]
    app.dependency_overrides[proveedor] = lambda: Falso()
    r=TestClient(app).get('/api/v1/vpn/me')
    assert r.status_code == 200
    assert r.json()['username'] == 'rf5_inv_001'
    assert r.json()['count'] == 1


def test_logout_rest_desconecta_cuenta_de_rf2_y_revoca(monkeypatch, tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import src.vpn_rest_as.rf4 as mod
    from src.rf2.rutas import sesion_autenticada, obtener_token
    from src.vpn_rest_as.rutas import proveedor
    app = FastAPI()
    app.include_router(mod.router)
    app.dependency_overrides[sesion_autenticada] = lambda: {'username':'rf5_inv_001', 'device_id':'dispositivo1'}
    app.dependency_overrides[obtener_token] = lambda: 'token1'
    acciones=[]
    class Falso:
        def fijar_acceso(self, username, *, permitido):
            acciones.append(('bloquear',username, permitido))
        def desconectar_usuario(self, username):
            acciones.append(('desconectar',username))
            return {}
        def esperar_desconexion(self, username):
            acciones.append(('verificar_desconexion', username))
            return {'status':'disconnected_verified'}
    app.dependency_overrides[proveedor] = lambda: Falso()
    monkeypatch.setattr(mod, 'bloquear_concesiones_usuario', lambda username, ruta: acciones.append(('revocar',username)))
    monkeypatch.setattr(mod, 'registrar_cierre', lambda *a,**k: None)
    r=TestClient(app).post('/api/v1/sessions/logout')
    assert r.status_code == 200
    assert r.json()['status'] == 'closed'
    assert acciones == [('bloquear','rf5_inv_001', False),('desconectar','rf5_inv_001'),('verificar_desconexion','rf5_inv_001'),('revocar','rf5_inv_001')]


def test_logout_rest_fallo_vpn_no_revoca_web(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import src.vpn_rest_as.rf4 as mod
    from src.rf2.rutas import sesion_autenticada, obtener_token
    from src.vpn_rest_as.rutas import proveedor
    app = FastAPI()
    app.include_router(mod.router)
    app.dependency_overrides[sesion_autenticada] = lambda: {'username':'rf5_inv_001', 'device_id':'dispositivo1'}
    app.dependency_overrides[obtener_token] = lambda: 'token1'
    class Falso:
        def fijar_acceso(self, username, *, permitido):
            raise AccessServerError('sin conexión')
        def desconectar_usuario(self, _):
            raise AccessServerError('sin conexión')
    app.dependency_overrides[proveedor] = lambda: Falso()
    monkeypatch.setattr(mod, 'bloquear_concesiones_usuario', lambda *args,**kwargs: None)
    r=TestClient(app).post('/api/v1/sessions/logout')
    assert r.status_code == 503
