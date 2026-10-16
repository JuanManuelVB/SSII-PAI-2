"""Pruebas locales de la PKI X.509 estricta y autorización por REST.
No realiza instalación del SO ni modifica un Access Server real.
"""
from __future__ import annotations
import subprocess
from pathlib import Path

import httpx
from cryptography import x509
from pki.scripts.pki import crear_ca, emitir_servidor
from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer


def test_certificados_nuevos_tienen_aki_ski_y_validacion_estricta(tmp_path):
    crear_ca(tmp_path)
    emitir_servidor(tmp_path, nombre="localhost")
    root = tmp_path / "pki"
    for target in ("ca/ca.crt", "server/server.crt"):
        cert = x509.load_pem_x509_certificate((root / target).read_bytes())
        cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    salida = subprocess.run([
        "openssl", "verify", "-x509_strict", "-purpose", "sslserver",
        "-verify_hostname", "localhost", "-CAfile", str(root / "ca/ca.crt"),
        str(root / "server/server.crt")
    ], text=True, capture_output=True)
    assert salida.returncode == 0, salida.stderr


def test_fijar_acceso_por_rest_aplica_cambio_warm_sin_socket():
    rutas = []
    def handle(request: httpx.Request):
        rutas.append((request.method, request.url.path, request.url.query))
        if request.url.path == "/api/auth/login/userpassword":
            return httpx.Response(200, json={"auth_token": "simulado"})
        if request.url.path == "/api/userprop/set":
            return httpx.Response(200, json=[{"name": "rf5_inv_001"}])
        if request.url.path == "/api/server/restart":
            return httpx.Response(200, text="")
        return httpx.Response(404)
    svc = AccessServerClient(
        ConfigAccessServer("https://localhost:943", "openvpn", "un-secreto-test"),
        transport=httpx.MockTransport(handle),
    )
    resultado = svc.fijar_acceso("rf5_inv_001", permitido=False)
    assert resultado == {"status": "accepted", "http_status": 200}
    assert ("POST", "/api/server/restart", b"restartMode=warm") in rutas


def test_error_restart_no_se_comunica_como_autorizacion_exitosa():
    def handle(request: httpx.Request):
        if request.url.path == "/api/auth/login/userpassword":
            return httpx.Response(200, json={"auth_token": "simulado"})
        if request.url.path == "/api/userprop/set":
            return httpx.Response(200, text="OK")
        return httpx.Response(500, text="fallo")
    from src.vpn_rest_as.client import AccessServerError
    svc=AccessServerClient(ConfigAccessServer("https://localhost:943", "openvpn", "pass"),
                           transport=httpx.MockTransport(handle))
    import pytest
    with pytest.raises(AccessServerError,match="HTTP 500"):
        svc.fijar_acceso("rf5_inv_001", permitido=True)
