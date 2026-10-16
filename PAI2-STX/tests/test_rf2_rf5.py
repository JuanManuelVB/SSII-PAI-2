"""Asegura que RF2 funciona con un usuario RF5 real, no solo simulado."""

from __future__ import annotations

import base64
import csv

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient

from pki.scripts import pki
from src.gateway.app import app
from src.rf5.gestion import precargar_usuarios, emitir_certificados
from src.rf2.autenticacion import mensaje_a_firmar


def test_login_real_con_usuario_precargado_rf5(tmp_path, monkeypatch):
    pki.crear_ca(tmp_path)
    db = tmp_path / "rf5.sqlite3"
    cred = tmp_path / "credenciales.csv"
    ruta_ca = tmp_path / "pki/ca/ca.crt"
    directorio_clientes = tmp_path / "pki/clients/rf5"
    precargar_usuarios(total=3, ruta_base_datos=db, ruta_credenciales=cred)
    emitir_certificados(ruta_base_datos=db, directorio_destino=directorio_clientes,
                        ruta_ca_cert=ruta_ca, ruta_ca_key=tmp_path / "pki/ca/ca.key", limite=3)
    with cred.open(newline="", encoding="utf8") as archivo:
        cuenta = next(x for x in csv.DictReader(archivo) if x["username"] == "rf5_pdi_001")
    cert_path = directorio_clientes / "rf5_pdi_001.crt"
    clave_path = directorio_clientes / "rf5_pdi_001.key"
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(app.state, "ruta_base_datos", db, raising=False)
    monkeypatch.setattr(app.state, "ruta_ca", ruta_ca, raising=False)
    monkeypatch.setattr(app.state, "ruta_revocados", tmp_path / "pki/ca/revoked.json", raising=False)
    monkeypatch.setattr(app.state, "ruta_auditoria_rf4", tmp_path / "rf4_audit.jsonl", raising=False)

    async def adaptador_pruebas(scope, receive, send):
        if scope["type"] == "http":
            scope["mtls_client_cert_der"] = cert_der
        await app(scope, receive, send)

    with TestClient(adaptador_pruebas, base_url="https://testserver") as client:
        respuesta = client.post("/api/v1/sessions/challenge", json={
            "username": cuenta["username"], "device_id": cuenta["device_id"]
        })
        assert respuesta.status_code == 200
        nonce = respuesta.json()["nonce"]
        clave = serialization.load_pem_private_key(clave_path.read_bytes(), None)
        firma = clave.sign(mensaje_a_firmar(nonce, cuenta["username"], cuenta["device_id"]),
                           padding.PKCS1v15(), hashes.SHA256())
        login = client.post("/api/v1/sessions/login", json={
            "username": cuenta["username"], "password": cuenta["password"],
            "device_id": cuenta["device_id"], "nonce": nonce,
            "certificate": cert_path.read_text(),
            "signature": base64.b64encode(firma).decode(),
        })
        assert login.status_code == 200, login.text
        cab = {"Authorization": "Bearer " + login.json()["access_token"]}
        assert client.get("/api/v1/sessions/me", headers=cab).json()["role"] == "PDI"
        assert client.post("/api/v1/sessions/logout", headers=cab).status_code == 200
        assert client.get("/api/v1/sessions/me", headers=cab).status_code == 401
