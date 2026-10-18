"""Integración REAL HTTPS TLS1.3/mTLS ↔ RF2 ↔ RF4 sobre sockets."""

from __future__ import annotations

import base64
import socket
import ssl
import threading
import time

import httpx
import uvicorn
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pki.scripts import pki
from src.gateway.protocolo_mtls import MTLSH11Protocol
from src.rf2.autenticacion import mensaje_a_firmar
from src.server.tls import crear_contexto_tls_servidor
# Misma app que configura el fixture ``escenario`` (RF2/RF4 sin Access Server).
from test_rf2_rf4 import app, escenario  # noqa: F401  (fixture de pytest)


def test_login_logout_reales_por_tls13_mtls(escenario, tmp_path):
    pki.emitir_servidor(tmp_path)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, lifespan="on",
                            log_level="warning", proxy_headers=False, access_log=False, http=MTLSH11Protocol)
    config.load()
    config.ssl = crear_contexto_tls_servidor(
        ruta_ca=escenario["ca"],
        ruta_certificado=tmp_path / "pki/server/server.crt",
        ruta_clave=tmp_path / "pki/server/server.key",
    )
    server = uvicorn.Server(config)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(20)
    port = sock.getsockname()[1]
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        for _ in range(200):
            if server.started:
                break
            time.sleep(0.03)
        assert server.started, "El gateway no ha iniciado"

        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.verify_mode = ssl.CERT_REQUIRED
        client_context.check_hostname = True
        client_context.load_verify_locations(cafile=str(escenario["ca"]))
        client_context.minimum_version = ssl.TLSVersion.TLSv1_3
        client_context.maximum_version = ssl.TLSVersion.TLSv1_3
        client_context.load_cert_chain(certfile=str(escenario["cert"]), keyfile=str(escenario["key"]))
        with httpx.Client(verify=client_context, trust_env=False, base_url=f"https://localhost:{port}") as client:
            challenge = client.post("/api/v1/sessions/challenge", json={
                "username": "pdi_test", "device_id": "device-1"
            })
            assert challenge.status_code == 200, challenge.text
            nonce = challenge.json()["nonce"]
            key = serialization.load_pem_private_key(escenario["key"].read_bytes(), None)
            firma = key.sign(mensaje_a_firmar(nonce, "pdi_test", "device-1"), padding.PKCS1v15(), hashes.SHA256())
            login = client.post("/api/v1/sessions/login", json={
                "username": "pdi_test", "device_id": "device-1", "password": "contrasenaSegura123",
                "nonce": nonce, "certificate": escenario["cert"].read_text(),
                "signature": base64.b64encode(firma).decode(),
            })
            assert login.status_code == 200, login.text
            token = login.json()["access_token"]
            cab = {"Authorization": f"Bearer {token}"}
            assert client.get("/api/v1/sessions/me", headers=cab).status_code == 200
            # Token robado, pero presentado con OTRO certificado igualmente
            # válido para la misma CA: se rechaza la sesión por identidad TLS.
            contexto_otro = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            contexto_otro.verify_mode = ssl.CERT_REQUIRED
            contexto_otro.check_hostname = True
            contexto_otro.load_verify_locations(cafile=str(escenario["ca"]))
            contexto_otro.minimum_version = ssl.TLSVersion.TLSv1_3
            contexto_otro.maximum_version = ssl.TLSVersion.TLSv1_3
            contexto_otro.load_cert_chain(certfile=str(escenario["otro_cert"]), keyfile=str(escenario["otra_clave"]))
            with httpx.Client(verify=contexto_otro, trust_env=False, base_url=f"https://localhost:{port}") as otro:
                assert otro.get("/api/v1/sessions/me", headers=cab).status_code == 401
            assert client.post("/api/v1/sessions/logout", headers=cab).status_code == 200
            assert client.get("/api/v1/sessions/me", headers=cab).status_code == 401

        # Una conexión TLS con certificado ausente debe ser rechazada en handshake.
        sin_certificado = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sin_certificado.verify_mode = ssl.CERT_REQUIRED
        sin_certificado.check_hostname = True
        sin_certificado.load_verify_locations(cafile=str(escenario["ca"]))
        sin_certificado.minimum_version = ssl.TLSVersion.TLSv1_3
        sin_certificado.maximum_version = ssl.TLSVersion.TLSv1_3
        with httpx.Client(verify=sin_certificado, trust_env=False, base_url=f"https://localhost:{port}") as cliente:
            with pytest.raises(httpx.TransportError):
                cliente.get("/health")
    finally:
        server.should_exit = True
        thread.join(timeout=8)
        sock.close()
