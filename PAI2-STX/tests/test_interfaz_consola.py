"""Pruebas de consola sin abrir puertos, sin modificar la SQLite del grupo."""
from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.client.servicio_consola import (
    ClienteConsola, ErrorConsola, IdentidadLocal, encontrar_identidades, registrar_dispositivo,
)


def _material(tmp_path: Path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA laboratorio")])
    now = datetime.now(timezone.utc)
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_subject).issuer_name(ca_subject)
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=10))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    ca = tmp_path / "ca.crt"
    ca.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "dispositivo-1"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "alumno"),
    ])
    crt_obj = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=10))
               .sign(ca_key, hashes.SHA256()))
    root = tmp_path / "clients"
    root.mkdir()
    ruta_key = root / "alumno.key"
    ruta_crt = root / "alumno.crt"
    ruta_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    ruta_crt.write_bytes(crt_obj.public_bytes(serialization.Encoding.PEM))
    return ca, root, IdentidadLocal("alumno", "dispositivo-1", ruta_crt, ruta_key)


def test_descubrir_identidades_sin_abrir_claves(tmp_path):
    _, root, identidad = _material(tmp_path)
    resultado = encontrar_identidades(root)
    assert resultado == [identidad]
    identidad.clave.unlink()
    assert encontrar_identidades(root) == []


def test_login_logout_consulta_y_401_con_token_anterior(tmp_path):
    ca, _, identidad = _material(tmp_path)
    estado = {"revocado": False, "token": "token-privado", "challenge": None}
    llamadas = []

    def responder(request: httpx.Request) -> httpx.Response:
        llamadas.append((request.method, request.url.path))
        if request.url.path.endswith("/challenge"):
            body = __import__("json").loads(request.content)
            assert body["username"] == "alumno"
            return httpx.Response(200, json={"nonce": "nonce-de-laboratorio-12345678901234567890"})
        if request.url.path.endswith("/login"):
            body = __import__("json").loads(request.content)
            assert body["password"] == "clave-de-prueba"
            assert body["signature"]
            return httpx.Response(200, json={"access_token": estado["token"], "expires_at": "mañana"})
        assert request.headers.get("Authorization") == "Bearer " + estado["token"]
        if request.url.path.endswith("/logout"):
            estado["revocado"] = True
            return httpx.Response(200, json={"status": "closed"})
        if request.url.path.endswith("/me"):
            return httpx.Response(401 if estado["revocado"] else 200,
                                  json={"username": "alumno", "device_id": "dispositivo-1", "role": "PDI", "expires_at": "mañana"})
        raise AssertionError("ruta inesperada")

    def fabricar(**kwargs):
        assert isinstance(kwargs["verify"], ssl.SSLContext)
        assert kwargs["verify"].minimum_version == ssl.TLSVersion.TLSv1_3
        return httpx.Client(transport=httpx.MockTransport(responder), base_url=kwargs["base_url"])

    cliente = ClienteConsola(ca=ca, fabrica=fabricar)
    assert cliente.iniciar_sesion(identidad, "clave-de-prueba")["codigo"] == 200
    assert cliente.conectado
    assert cliente.consultar_sesion()["role"] == "PDI"
    fin = cliente.cerrar_sesion()
    assert fin.respuesta == 200 and fin.confirmacion and fin.rechazo_comprobado
    assert fin.codigo_comprobacion == 401
    assert not cliente.conectado
    assert llamadas == [("POST", "/api/v1/sessions/challenge"), ("POST", "/api/v1/sessions/login"),
                        ("GET", "/api/v1/sessions/me"), ("POST", "/api/v1/sessions/logout"),
                        ("GET", "/api/v1/sessions/me")]


def test_login_rechazado_no_guarda_token(tmp_path):
    ca, _, identidad = _material(tmp_path)
    def responder(req):
        return (httpx.Response(200, json={"nonce": "nonce-de-laboratorio-12345678901234567890"})
                if req.url.path.endswith("/challenge") else httpx.Response(401, json={"detail": "invalid credentials"}))
    def fabricar(**kwargs):
        return httpx.Client(transport=httpx.MockTransport(responder), base_url=kwargs["base_url"])
    cliente = ClienteConsola(ca=ca, fabrica=fabricar)
    with pytest.raises(ErrorConsola, match="401"):
        cliente.iniciar_sesion(identidad, "contraseña-incorrecta")
    assert not cliente.conectado


def test_rf1_alta_genera_clave_local_y_no_sobrescribe(tmp_path):
    ca, _, _ = _material(tmp_path)
    destino = tmp_path / "nuevas"
    now = datetime.now(timezone.utc)
    def responder(req):
        assert req.url.path == "/api/v1/devices/register"
        datos = __import__("json").loads(req.content)
        key = serialization.load_pem_public_key(datos["public_key"].encode("ascii"))
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dispositivo-nuevo"),
                            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "alumno")])
        certificado = (x509.CertificateBuilder().subject_name(sujeto).issuer_name(sujeto)
                       .public_key(key).serial_number(x509.random_serial_number())
                       .not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(days=5))
                       .sign(ca_key, hashes.SHA256()))
        return httpx.Response(201, json={"certificate":certificado.public_bytes(serialization.Encoding.PEM).decode("ascii")})
    def fabricar(**kwargs):
        return httpx.Client(transport=httpx.MockTransport(responder), base_url=kwargs["base_url"])
    identidad = registrar_dispositivo(usuario="alumno", password="clave-larga-segura",
                                       device_id="dispositivo-nuevo", ca=ca,
                                       directorio=destino, fabrica=fabricar)
    assert identidad.certificado.is_file() and identidad.clave.is_file()
    with pytest.raises(ErrorConsola, match="no se sobrescriben"):
        registrar_dispositivo(usuario="alumno", password="clave-larga-segura",
                             device_id="dispositivo-nuevo", ca=ca,
                             directorio=destino, fabrica=fabricar)


def test_rf1_alta_acepta_el_certificado_que_ya_guardo_el_servidor(tmp_path):
    """Regresión: en el laboratorio el servidor RF1 escribe el .crt en la misma carpeta."""
    ca, _, _ = _material(tmp_path)
    destino = tmp_path / "compartida"
    destino.mkdir()
    now = datetime.now(timezone.utc)
    emitidos = []

    def responder(req):
        datos = __import__("json").loads(req.content)
        key = serialization.load_pem_public_key(datos["public_key"].encode("ascii"))
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "disp-lab"),
                            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "alumno")])
        pem = (x509.CertificateBuilder().subject_name(sujeto).issuer_name(sujeto)
               .public_key(key).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=5))
               .sign(ca_key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM)
        (destino / "disp-lab.crt").write_bytes(pem)  # lo que hace el servidor RF1
        emitidos.append(pem)
        return httpx.Response(201, json={"certificate": pem.decode("ascii")})

    def fabricar(**kwargs):
        return httpx.Client(transport=httpx.MockTransport(responder), base_url=kwargs["base_url"])

    identidad = registrar_dispositivo(usuario="alumno", password="clave-larga-segura",
                                      device_id="disp-lab", ca=ca, directorio=destino,
                                      fabrica=fabricar)
    assert identidad.certificado.read_bytes() == emitidos[0]
    assert identidad.clave.is_file()


def test_no_acepta_http_en_gateway_y_registro(tmp_path):
    ca, _, _ = _material(tmp_path)
    with pytest.raises(ValueError, match="HTTPS"):
        ClienteConsola(url="http://localhost:8443", ca=ca)
    with pytest.raises(ErrorConsola, match="HTTPS"):
        registrar_dispositivo(usuario="alumno", password="clave-larga-segura",
                             device_id="nuevo", url_registro="http://localhost:8444", ca=ca)
