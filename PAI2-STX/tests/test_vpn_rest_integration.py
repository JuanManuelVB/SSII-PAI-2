"""Pruebas de la integración BYODSEC/AS sin servidores externos ni secretos."""
import os
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer, AccessServerError
from src.rf2.rutas import obtener_token, sesion_autenticada
from src.vpn_rest_as.rutas import proveedor, router as vpn_router
import src.vpn_rest_as.rf4 as logout_mod
import src.vpn_rest_as.rutas as vpn_mod


def mock_api():
    recorded = []
    connected = {'active': True}
    def handler(req):
        recorded.append((req.method, req.url.path, req.content))
        if req.url.path == '/api/auth/login/userpassword':
            return httpx.Response(200, json={'auth_token': 't'})
        if req.url.path == '/api/vpn/status':
            return httpx.Response(200, json={'vpn_clients': [{'username':'rf5_inv_001'}] if connected['active'] else []})
        if req.url.path == '/api/userprop/set':
            return httpx.Response(200, json={})
        if req.url.path == '/api/vpn/client/disconnect':
            connected['active'] = False
            return httpx.Response(200, json={})
        if req.url.path == '/api/server/restart':
            return httpx.Response(200, text='')
        if req.url.path == '/api/users/create':
            return httpx.Response(201, json={})
        raise AssertionError('Ruta inesperada: '+req.url.path)
    return AccessServerClient(ConfigAccessServer('https://as.test', 'admin', 'pw'), httpx.MockTransport(handler)), recorded


def test_acceso_denegar_y_habilitar_por_rest():
    api, r = mock_api()
    api.fijar_acceso('rf5_inv_001', permitido=False)
    api.fijar_acceso('rf5_inv_001', permitido=True)
    calls = [x[2] for x in r if x[1] == '/api/userprop/set']
    assert b'"deny":true' in calls[0] or b'"deny": true' in calls[0]
    assert b'"deny":false' in calls[1] or b'"deny": false' in calls[1]
    assert all(b'"autologin": false' in c or b'"autologin":false' in c for c in calls)


def test_alta_se_crea_bloqueada_y_no_admin():
    api, r=mock_api()
    api.crear_usuario_bloqueado('rf5_inv_001')
    body=next(x[2] for x in r if x[1]=='/api/users/create')
    assert b'"deny":true' in body or b'"deny": true' in body
    assert b'"admin":false' in body or b'"admin": false' in body


def test_autorizacion_sin_politica_confirmada_se_rechaza(monkeypatch):
    monkeypatch.delenv('BYODSEC_VPN_DEFAULT_DENY', raising=False)
    app=FastAPI(); app.include_router(vpn_router)
    app.dependency_overrides[sesion_autenticada] = lambda: {'username':'rf5_inv_001','device_id':'dev'}
    app.dependency_overrides[obtener_token] = lambda: 'token'
    api, r=mock_api(); app.dependency_overrides[proveedor]=lambda:api
    resp=TestClient(app).post('/api/v1/vpn/authorize')
    assert resp.status_code == 503
    assert r == []


def test_autorizacion_por_identidad_rf2_y_hash(monkeypatch, tmp_path):
    monkeypatch.setenv('BYODSEC_VPN_DEFAULT_DENY', 'confirmed')
    app=FastAPI(); app.include_router(vpn_router)
    app.state.ruta_base_datos = tmp_path/'test.sqlite3'
    app.dependency_overrides[sesion_autenticada] = lambda: {'username':'rf5_inv_001','device_id':'dev'}
    app.dependency_overrides[obtener_token] = lambda: 'super_secret_token'
    api,r=mock_api(); app.dependency_overrides[proveedor]=lambda:api
    resp=TestClient(app).post('/api/v1/vpn/authorize', json={'username':'other'})
    assert resp.status_code == 200
    assert resp.json()['username'] == 'rf5_inv_001'
    import sqlite3
    db=sqlite3.connect(app.state.ruta_base_datos)
    row=db.execute('SELECT username,token_hash FROM vpn_grants').fetchone()
    assert row[0]=='rf5_inv_001' and row[1]!='super_secret_token'
    assert b'rf5_inv_001' in next(v for _,url,v in r if url=='/api/userprop/set')


def test_logout_bloquea_corta_y_revoca_cuenta_completa(monkeypatch, tmp_path):
    from src.common.base_datos import conectar_base_datos, inicializar_base_datos, ahora
    from src.rf2.sesiones import inicializar_sesiones, _hash_token
    db=tmp_path/'test.sqlite3'; inicializar_sesiones(db)
    with conectar_base_datos(db) as c:
        c.execute("INSERT INTO users(username,password_hash,role,status,created_at,updated_at) VALUES('rf5_inv_001','hash','PDI','active',?,?)",(ahora(),ahora()))
        c.execute("INSERT INTO device_pairings(device_id,username,public_key_fingerprint,certificate_serial,created_at,status) VALUES('dev','rf5_inv_001','fp','1',?,'active')",(ahora(),))
        c.execute("INSERT INTO sessions(token_hash,username,device_id,certificate_serial,created_at,expires_at) VALUES(?,?,?,?,?,?)",(_hash_token('tok'),'rf5_inv_001','dev','1',ahora(),'2999-01-01T00:00:00+00:00'))
        c.execute("INSERT INTO sessions(token_hash,username,device_id,certificate_serial,created_at,expires_at) VALUES(?,?,?,?,?,?)",(_hash_token('old'),'rf5_inv_001','dev','1',ahora(),'2999-01-01T00:00:00+00:00'))
    app=FastAPI(); app.include_router(logout_mod.router)
    app.state.ruta_base_datos=db; app.state.ruta_auditoria_rf4=tmp_path/'audit.jsonl'
    app.dependency_overrides[sesion_autenticada]=lambda:{'username':'rf5_inv_001','device_id':'dev'}
    app.dependency_overrides[obtener_token]=lambda:'tok'
    api, calls=mock_api(); app.dependency_overrides[proveedor]=lambda:api
    r=TestClient(app).post('/api/v1/sessions/logout')
    assert r.status_code==200
    assert r.json()['status']=='closed'
    with conectar_base_datos(db) as c:
        assert c.execute('SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL').fetchone()[0]==0
    ops=[path for _,path,_ in calls if path != '/api/auth/login/userpassword']
    assert ops==['/api/userprop/set','/api/server/restart','/api/vpn/client/disconnect','/api/vpn/status']


def test_fallo_rest_revoca_tokens_de_aplicacion(monkeypatch,tmp_path):
    from src.common.base_datos import conectar_base_datos, inicializar_base_datos, ahora
    from src.rf2.sesiones import inicializar_sesiones, _hash_token
    db=tmp_path/'test.sqlite3'; inicializar_sesiones(db)
    with conectar_base_datos(db) as c:
        c.execute("INSERT INTO users(username,password_hash,role,status,created_at,updated_at) VALUES('rf5_inv_001','hash','PDI','active',?,?)",(ahora(),ahora()))
        c.execute("INSERT INTO device_pairings(device_id,username,public_key_fingerprint,certificate_serial,created_at,status) VALUES('dev','rf5_inv_001','fp','1',?,'active')",(ahora(),))
        c.execute("INSERT INTO sessions(token_hash,username,device_id,certificate_serial,created_at,expires_at) VALUES(?,?,?,?,?,?)",(_hash_token('tok'),'rf5_inv_001','dev','1',ahora(),'2999-01-01T00:00:00+00:00'))
    class Failing:
        def fijar_acceso(self,*args,**kwargs): raise AccessServerError('error')
        def desconectar_usuario(self,*args,**kwargs): raise AccessServerError('error')
    app=FastAPI(); app.include_router(logout_mod.router)
    app.state.ruta_base_datos=db; app.state.ruta_auditoria_rf4=tmp_path/'audit.jsonl'
    app.dependency_overrides[sesion_autenticada]=lambda:{'username':'rf5_inv_001','device_id':'dev'}
    app.dependency_overrides[obtener_token]=lambda:'tok'
    app.dependency_overrides[proveedor]=lambda:Failing()
    r=TestClient(app).post('/api/v1/sessions/logout')
    assert r.status_code==503
    with conectar_base_datos(db) as c:
        assert c.execute('SELECT revoked_at FROM sessions').fetchone()[0] is not None
