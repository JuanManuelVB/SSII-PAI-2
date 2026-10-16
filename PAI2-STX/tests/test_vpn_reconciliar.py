from datetime import datetime,timezone,timedelta
from src.common.base_datos import conectar_base_datos,inicializar_base_datos,ahora
from src.rf2.sesiones import inicializar_sesiones,_hash_token
from src.vpn_rest_as.autorizaciones import guardar_concesion
from src.vpn_rest_as.reconciliar import usuarios_sin_sesion_valida,ejecutar


def test_caducidad_bloquea_y_desconecta(tmp_path):
    path=tmp_path/'test.sqlite3'
    inicializar_sesiones(path)
    with conectar_base_datos(path) as c:
        c.execute("INSERT INTO users(username,password_hash,role,status,created_at,updated_at) VALUES('demo','hash','PDI','active',?,?)",(ahora(),ahora()))
        c.execute("INSERT INTO device_pairings(device_id,username,public_key_fingerprint,certificate_serial,created_at,status) VALUES('dev','demo','fp','1',?,'active')",(ahora(),))
        c.execute("INSERT INTO sessions(token_hash,username,device_id,certificate_serial,created_at,expires_at) VALUES(?,?,?,?,?,?)",(_hash_token('tok'),'demo','dev','1',ahora(),(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat()))
    guardar_concesion('tok','demo','dev',path)
    assert usuarios_sin_sesion_valida(path)==[]
    with conectar_base_datos(path) as c:
        c.execute("UPDATE sessions SET expires_at='2020-01-01T00:00:00+00:00'")
    assert usuarios_sin_sesion_valida(path)==['demo']
    ops=[]
    class Fake:
        def fijar_acceso(self,u,*,permitido): ops.append(('block',u,permitido))
        def desconectar_usuario(self,u): ops.append(('disconnect',u))
    assert ejecutar(Fake(),path)==['demo']
    assert ops==[('block','demo',False),('disconnect','demo')]
    assert usuarios_sin_sesion_valida(path)==[]
