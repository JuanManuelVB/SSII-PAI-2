"""Pruebas de RF1: registro y emparejamiento de un dispositivo BYOD."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi.testclient import TestClient

from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.common.seguridad import crear_hash_contrasena
from src.server import app as server


def _clave_publica_pem() -> str:
    """Genera la clave pública que simula la clave creada en el dispositivo."""
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return clave.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _preparar_usuario(ruta_base_datos, username: str = "rf1_pdi") -> None:
    """Crea una cuenta de prueba con el mismo hash usado por RF1."""
    inicializar_base_datos(ruta_base_datos)
    with conectar_base_datos(ruta_base_datos) as conexion:
        conexion.execute(
            """
            INSERT INTO users
            (username, password_hash, role, status, created_at, updated_at)
            VALUES (?, ?, 'PDI', 'active', '2026-01-01', '2026-01-01')
            """,
            (username, crear_hash_contrasena("contrasena-rf1-segura")),
        )


def _configurar_rf1_aislado(monkeypatch, tmp_path, ruta_base_datos) -> None:
    """CA, certificados, SQLite y auditoría temporales: nada toca el proyecto."""
    from pki.scripts import pki

    pki.crear_ca(tmp_path)
    monkeypatch.setattr(server, "RAIZ", tmp_path)
    monkeypatch.setattr(server, "RUTA_BASE_DATOS", ruta_base_datos)
    monkeypatch.setattr(server, "RUTA_CERTIFICADO_CA", tmp_path / "pki" / "ca" / "ca.crt")
    monkeypatch.setattr(server, "RUTA_CLAVE_CA", tmp_path / "pki" / "ca" / "ca.key")
    monkeypatch.setattr(server, "DIRECTORIO_CERTIFICADOS_CLIENTE", tmp_path / "pki" / "clients")


def test_health_endpoint():
    with TestClient(server.app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_registro_rechaza_credenciales_invalidas(tmp_path, monkeypatch):
    print("[RF1] Enviando un registro con credenciales inválidas")
    ruta_base_datos = tmp_path / "rf1.sqlite3"
    _preparar_usuario(ruta_base_datos)
    _configurar_rf1_aislado(monkeypatch, tmp_path, ruta_base_datos)
    with TestClient(server.app) as client:
        response = client.post("/api/v1/devices/register", json={
            "username": "rf1_pdi", "password": "contrasena-incorrecta",
            "device_id": "device-1", "public_key": _clave_publica_pem(),
        })
    assert response.status_code == 401
    print("[RF1] Registro rechazado con HTTP 401")


def test_registro_emite_certificado_y_persiste_emparejamiento(tmp_path, monkeypatch):
    """El alta debe emitir un certificado y guardar su vínculo completo."""
    print("[RF1] Preparando usuario activo, CA temporal y base SQLite aislada")
    ruta_base_datos = tmp_path / "rf1.sqlite3"
    _preparar_usuario(ruta_base_datos)
    _configurar_rf1_aislado(monkeypatch, tmp_path, ruta_base_datos)

    clave_publica = _clave_publica_pem()
    print("[RF1] Enviando clave pública RSA para registrar el dispositivo BYOD")
    with TestClient(server.app) as cliente:
        respuesta = cliente.post(
            "/api/v1/devices/register",
            json={
                "username": "rf1_pdi",
                "password": "contrasena-rf1-segura",
                "device_id": "byod-rf1-001",
                "public_key": clave_publica,
            },
        )

    assert respuesta.status_code == 201, respuesta.text
    datos = respuesta.json()
    assert datos["status"] == "registered"
    assert datos["certificate"].startswith("-----BEGIN CERTIFICATE-----")
    assert datos["ca_certificate"].startswith("-----BEGIN CERTIFICATE-----")
    print("[RF1] Certificado cliente y certificado CA devueltos por la API")

    with conectar_base_datos(ruta_base_datos) as conexion:
        emparejamiento = conexion.execute(
            """
            SELECT username, device_id, public_key_fingerprint,
                   certificate_serial, certificate_path, status
            FROM device_pairings
            """
        ).fetchone()

    assert tuple(emparejamiento[:2]) == ("rf1_pdi", "byod-rf1-001")
    assert emparejamiento["certificate_serial"] == datos["certificate_serial"]
    assert emparejamiento["certificate_path"] == "pki/clients/byod-rf1-001.crt"
    assert emparejamiento["status"] == "active"
    print(
        "[RF1] Emparejamiento persistido: usuario, dispositivo, huella, "
        "serie, ruta y estado activo"
    )

    certificado = server.x509.load_pem_x509_certificate(
        (tmp_path / "pki" / "clients" / "byod-rf1-001.crt").read_bytes()
    )
    eku = certificado.extensions.get_extension_for_class(
        server.x509.ExtendedKeyUsage
    ).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    print("[RF1] Certificado almacenado con uso exclusivo clientAuth")


def test_registro_rechaza_reutilizar_dispositivo_o_clave(tmp_path, monkeypatch):
    """Un dispositivo y una clave pública no se pueden volver a emparejar."""
    print("[RF1] Registrando el primer emparejamiento válido")
    ruta_base_datos = tmp_path / "rf1.sqlite3"
    _preparar_usuario(ruta_base_datos)
    _configurar_rf1_aislado(monkeypatch, tmp_path, ruta_base_datos)
    clave_publica = _clave_publica_pem()
    solicitud = {
        "username": "rf1_pdi",
        "password": "contrasena-rf1-segura",
        "device_id": "byod-rf1-002",
        "public_key": clave_publica,
    }

    with TestClient(server.app) as cliente:
        primera = cliente.post("/api/v1/devices/register", json=solicitud)
        mismo_dispositivo = cliente.post(
            "/api/v1/devices/register",
            json={**solicitud, "public_key": _clave_publica_pem()},
        )
        misma_clave = cliente.post(
            "/api/v1/devices/register",
            json={**solicitud, "device_id": "byod-rf1-003"},
        )

    assert primera.status_code == 201
    print("[RF1] Intentando reutilizar el mismo device_id con otra clave")
    assert mismo_dispositivo.status_code == 409
    print("[RF1] Intentando reutilizar la misma clave con otro device_id")
    assert misma_clave.status_code == 409
    print("[RF1] Ambas reutilizaciones fueron rechazadas con HTTP 409")
