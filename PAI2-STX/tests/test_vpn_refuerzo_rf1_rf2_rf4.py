"""Refuerzo RF1/RF2/RF4 con VPN: inmutabilidad, abort, un dispositivo por cuenta, perfiles userlogin."""
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.common.base_datos import conectar_base_datos, ahora
from src.rf2.sesiones import inicializar_sesiones, crear_sesion, revocar_token, validar_sesion
from src.vpn_rest_as.autorizaciones import (guardar_concesion, hay_concesion_de_otro_dispositivo)
from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer, AccessServerError
from src.rf2.rutas import sesion_autenticada, obtener_token
from src.vpn_rest_as.rutas import proveedor, router as vpn_router
import src.vpn_rest_as.rf4 as rf4
from tools.probar_tunel import comprobar
from tools.auditar_rf1_rf5_pki import comprobar as auditoria


def seed(db, device='dev1'):
    inicializar_sesiones(db)
    with conectar_base_datos(db) as conn:
        conn.execute("INSERT INTO users(username,password_hash,role,status,origin,created_at,updated_at) VALUES ('rf5_inv_001','hash','INVESTIGADOR','active','RF5',?,?)", (ahora(),ahora()))
        conn.execute("INSERT INTO device_pairings(device_id,username,public_key_fingerprint,certificate_serial,created_at,status) VALUES (?, 'rf5_inv_001', 'fp1', '11', ?, 'active')", (device, ahora()))


def test_rf1_inmutabilidad_sqlite_y_revocacion_permitida(tmp_path):
    db=tmp_path/'db.sqlite3'
    seed(db)
    with conectar_base_datos(db) as conn:
        import sqlite3
        with pytest.raises(sqlite3.IntegrityError, match='RF1'):
            conn.execute("UPDATE device_pairings SET public_key_fingerprint='otra' WHERE device_id='dev1'")
        with pytest.raises(sqlite3.IntegrityError, match='RF1'):
            conn.execute("UPDATE users SET username='nuevo' WHERE username='rf5_inv_001'")
        conn.execute("UPDATE device_pairings SET status='revoked' WHERE device_id='dev1'")
        assert conn.execute("SELECT status FROM device_pairings WHERE device_id='dev1'").fetchone()[0]=='revoked'


def test_rf2_token_abort_revoca_solo_token(tmp_path):
    db=tmp_path/'db.sqlite3'; seed(db)
    token, _=crear_sesion('rf5_inv_001','dev1','11',db)
    assert validar_sesion(token,db) is not None
    assert revocar_token(token,db) is True
    assert validar_sesion(token,db) is None
    assert revocar_token(token,db) is False


def test_rf2_rechaza_segundo_dispositivo_con_vpn_activa(tmp_path):
    db=tmp_path/'db.sqlite3';seed(db)
    token,_=crear_sesion('rf5_inv_001','dev1','11',db)
    guardar_concesion(token,'rf5_inv_001','dev1',db)
    assert hay_concesion_de_otro_dispositivo('rf5_inv_001','dev2',db)
    assert not hay_concesion_de_otro_dispositivo('rf5_inv_001','dev1',db)


def test_rf4_verifica_que_no_haya_tunel_rest():
    conexiones=[1,1,0]
    def handler(r):
        if r.url.path.endswith('/auth/login/userpassword'):
            return httpx.Response(200,json={'auth_token':'token_admin'})
        if r.url.path == '/api/vpn/status':
            activo=conexiones.pop(0)
            return httpx.Response(200,json={'vpn_clients':[{'username':'rf5_inv_001'}] if activo else []})
        raise AssertionError(r.url.path)
    api=AccessServerClient(ConfigAccessServer('https://as.test','adm','pw'),httpx.MockTransport(handler))
    assert api.esperar_desconexion('rf5_inv_001', intentos=3, espera=0)['status']=='disconnected_verified'


def test_rf4_no_da_confirmacion_si_as_sigue_conectado():
    def handler(r):
        if r.url.path.endswith('/auth/login/userpassword'):
            return httpx.Response(200,json={'auth_token':'token_admin'})
        return httpx.Response(200,json={'vpn_clients':[{'username':'rf5_inv_001'}]})
    api=AccessServerClient(ConfigAccessServer('https://as.test','adm','pw'),httpx.MockTransport(handler))
    with pytest.raises(AccessServerError, match='sigue conectada'):
        api.esperar_desconexion('rf5_inv_001', intentos=2, espera=0)


def test_vpn_perfil_generado_es_userlogin_nunca_autologin():
    calls=[]
    def handler(r):
        calls.append(r)
        if r.url.path.endswith('/auth/login/userpassword'):
            return httpx.Response(200,json={'auth_token':'token_admin'})
        assert r.url.path=='/api/profiles/create'
        assert r.headers['Accept']=='application/x-openvpn-profile'
        payload=__import__('json').loads(r.content)
        assert payload['username']=='rf5_inv_001'
        assert payload['profile_type']=='userlogin'
        assert payload['tls_crypt_v2'] is True
        return httpx.Response(201,content=b'client\n<cert>\ndemo\n</cert>\n')
    api=AccessServerClient(ConfigAccessServer('https://as.test','adm','pw'),httpx.MockTransport(handler))
    assert b'client' in api.generar_perfil_usuario('rf5_inv_001')
    assert len(calls)==2


def test_rf5_rs1_auditoria_detecta_incompleto(tmp_path):
    db=tmp_path/'db.sqlite3';seed(db)
    result=auditoria(db,tmp_path/'ca_missing.crt',tmp_path,300)
    assert not result['aprobado']
    assert result['problemas']


def test_tunel_rechaza_localhost_y_ip_publica():
    with pytest.raises(ValueError): comprobar('127.0.0.1')
    with pytest.raises(ValueError): comprobar('8.8.8.8')


def test_abort_endpoint_rechaza_nuevo_uso_del_token(tmp_path):
    db=tmp_path/'db.sqlite3';seed(db)
    token,_=crear_sesion('rf5_inv_001','dev1','11',db)
    app=FastAPI();app.include_router(rf4.router)
    app.state.ruta_base_datos=db
    app.dependency_overrides[sesion_autenticada]=lambda:{'username':'rf5_inv_001','device_id':'dev1'}
    app.dependency_overrides[obtener_token]=lambda:token
    assert TestClient(app).post('/api/v1/sessions/abort').status_code==204
    assert validar_sesion(token,db) is None


def test_rf4_si_la_vpn_sigue_activa_nunca_responde_200(tmp_path):
    db=tmp_path/'db.sqlite3';seed(db)
    token,_=crear_sesion('rf5_inv_001','dev1','11',db)
    app=FastAPI();app.include_router(rf4.router)
    app.state.ruta_base_datos=db
    app.state.ruta_auditoria_rf4=tmp_path/'audit.jsonl'
    app.dependency_overrides[sesion_autenticada]=lambda:{'username':'rf5_inv_001','device_id':'dev1'}
    app.dependency_overrides[obtener_token]=lambda:token
    class Fake:
        def fijar_acceso(self,*a,**kw):return {'status':'accepted'}
        def desconectar_usuario(self,*a,**kw):return {'status':'accepted'}
        def esperar_desconexion(self,*a,**kw):raise AccessServerError('sigue conectada')
    app.dependency_overrides[proveedor]=lambda:Fake()
    r=TestClient(app).post('/api/v1/sessions/logout')
    assert r.status_code==503
    assert validar_sesion(token,db) is None
    assert 'session_closed' not in (tmp_path/'audit.jsonl').read_text()


def test_rf2_si_authorize_falla_revoca_token_y_compensa(tmp_path,monkeypatch):
    db=tmp_path/'db.sqlite3';seed(db)
    token,_=crear_sesion('rf5_inv_001','dev1','11',db)
    monkeypatch.setenv('BYODSEC_VPN_DEFAULT_DENY','confirmed')
    app=FastAPI();app.include_router(vpn_router)
    app.state.ruta_base_datos=db
    app.dependency_overrides[sesion_autenticada]=lambda:{'username':'rf5_inv_001','device_id':'dev1'}
    app.dependency_overrides[obtener_token]=lambda:token
    llamadas=[]
    class Fake:
        def fijar_acceso(self,usr,*,permitido):
            llamadas.append(('permisos',permitido))
            if permitido:raise AccessServerError('fallo al autorizar')
        def desconectar_usuario(self,usr):llamadas.append(('desconectar',usr))
    app.dependency_overrides[proveedor]=lambda:Fake()
    r=TestClient(app).post('/api/v1/vpn/authorize')
    assert r.status_code==503
    assert validar_sesion(token,db) is None
    assert ('permisos',False) in llamadas
    assert ('desconectar','rf5_inv_001') in llamadas
