"""Dos identidades reales sobre TLS/mTLS con barrera y mensajes protegidos."""
from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
import threading
import time

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from pki.scripts import pki
from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.common.seguridad import crear_hash_contrasena
from src.gateway.app import crear_app
from src.gateway.protocolo_mtls import MTLSH11Protocol
from src.server.tls import crear_contexto_tls_servidor
from tools import carga_gateway
from tools.carga_300_sesiones import ejecutar


def test_dos_sesiones_sobre_tls13_mtls_y_mensajes(tmp_path, monkeypatch):
    # Material criptográfico efímero de PRUEBA, en tmp_path, no adjunto al ZIP.
    pki.crear_ca(tmp_path)
    pki.emitir_servidor(tmp_path)
    identidades = []
    database = tmp_path / "temporal.sqlite3"
    inicializar_base_datos(database)
    for idx in (1, 2):
        usuario, dispositivo = f"carga_{idx}", f"carga-{idx}-dev01"
        pki.emitir_cliente(tmp_path, dispositivo)
        carpeta = tmp_path / "pki" / "clients" / dispositivo
        crt = carpeta / f"{dispositivo}.crt"
        key = carpeta / f"{dispositivo}.key"
        cert = x509.load_pem_x509_certificate(crt.read_bytes())
        fp = hashlib.sha256(cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        with conectar_base_datos(database) as c:
            c.execute("""INSERT INTO users(username, password_hash, role, status, origin,created_at,updated_at)
                         VALUES (?,?, 'PDI', 'active', 'MANUAL', 'ahora','ahora')""",
                      (usuario, crear_hash_contrasena("secreto-de-prueba-123")))
            c.execute("""INSERT INTO device_pairings(device_id,username,public_key_fingerprint,
                         certificate_serial,certificate_path,created_at,status)
                         VALUES (?,?,?,?,?,'ahora','active')""",
                      (dispositivo, usuario, fp, str(cert.serial_number), str(crt)))
        identidades.append({"usuario": usuario, "device_id": dispositivo, "cert": crt,
                            "key": key, "password": "secreto-de-prueba-123"})

    app = crear_app(vpn_rest=False)
    app.state.ruta_base_datos = database
    app.state.ruta_ca = tmp_path / "pki" / "ca" / "ca.crt"
    app.state.ruta_revocados = tmp_path / "pki" / "ca" / "revoked.json"
    app.state.ruta_auditoria_accesos = tmp_path / "accesos.jsonl"
    app.state.ruta_auditoria_rf4 = tmp_path / "logout.jsonl"
    cfg = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", proxy_headers=False,
                         access_log=False, http=MTLSH11Protocol, timeout_keep_alive=30)
    cfg.load()
    cfg.ssl = crear_contexto_tls_servidor(ruta_ca=app.state.ruta_ca,
                ruta_certificado=tmp_path / "pki/server/server.crt",
                ruta_clave=tmp_path / "pki/server/server.key")
    serv = uvicorn.Server(cfg)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(100)
    puerto = sock.getsockname()[1]
    hilo = threading.Thread(target=serv.run, kwargs={"sockets": [sock]}, daemon=True)
    monkeypatch.setattr(carga_gateway, "CA", app.state.ruta_ca)
    hilo.start()
    try:
        for _ in range(150):
            if serv.started:
                break
            time.sleep(.05)
        assert serv.started
        resultado = asyncio.run(ejecutar(f"https://localhost:{puerto}", usuarios=2,
                                        duracion=3, preparacion=30, intervalo=.6,
                                        identidades=identidades))
        assert resultado["resultado"] == "APROBADO", resultado
        assert resultado["sesiones_validas_en_barrera"] == 2
        assert resultado["usuarios_completaron_periodo_con_mensajes"] == 2
        assert resultado["mensajes_protegidos_confirmados"] >= 2
        assert resultado["cierres_sesion_correctos"] == 2
        assert resultado["tokens_rechazados_tras_logout"] == 2
    finally:
        serv.should_exit = True
        hilo.join(timeout=8)
        sock.close()


def test_no_repiten_identidades_para_fingir_300():
    ejemplo = {"usuario": "persona1", "device_id": "device-1",
               "cert": None, "key": None, "password": "no-utilizada"}
    with pytest.raises(ValueError, match="identidades RF5 completas"):
        asyncio.run(ejecutar("https://localhost:9443", usuarios=300, duracion=2,
                             preparacion=5, intervalo=1, identidades=[ejemplo]))


def test_rechaza_http_sin_tls():
    with pytest.raises(ValueError, match="HTTPS"):
        asyncio.run(ejecutar("http://localhost:9443", usuarios=1, duracion=2,
                             preparacion=5, intervalo=1, identidades=[]))
