"""Pruebas de identidad y autorización del certificado cliente."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.server.tls import (
    buscar_emparejamiento_certificado,
    obtener_huella_clave_certificado,
)

from test_mtls import _crear_material_mtls


def test_certificado_cliente_se_asocia_con_el_emparejamiento_activo(tmp_path):
    """La huella del certificado debe localizar el dispositivo activo."""
    rutas = _crear_material_mtls(tmp_path)
    certificado_der = x509.load_pem_x509_certificate(
        rutas["certificado_cliente"].read_bytes()
    ).public_bytes(
        serialization.Encoding.DER
    )
    huella = obtener_huella_clave_certificado(certificado_der)
    ruta_db = tmp_path / "rf1.sqlite3"
    inicializar_base_datos(ruta_db)
    with conectar_base_datos(ruta_db) as conexion:
        conexion.execute(
            """
            INSERT INTO users
            (username, password_hash, role, status, origin, created_at, updated_at)
            VALUES ('cliente-prueba', 'hash-no-usado', 'PDI', 'active', 'MANUAL', 'now', 'now')
            """
        )
        conexion.execute(
            """
            INSERT INTO device_pairings
            (device_id, username, public_key_fingerprint, certificate_serial,
             certificate_path, created_at, status)
            VALUES ('device-001', 'cliente-prueba', ?, '123', 'cliente.crt', 'now', 'active')
            """,
            (huella,),
        )

    emparejamiento = buscar_emparejamiento_certificado(
        certificado_der,
        ruta_base_datos=ruta_db,
    )
    assert emparejamiento is not None
    assert emparejamiento["device_id"] == "device-001"
    assert emparejamiento["username"] == "cliente-prueba"
    print(
        "[IDENTIDAD] Huella derivada del certificado coincide con "
        "device_pairings y el dispositivo está activo"
    )


def test_certificado_valido_pero_no_emparejado_es_rechazado(tmp_path):
    """Un certificado de la CA no autorizado en SQLite no encuentra pareja."""
    rutas = _crear_material_mtls(tmp_path)
    certificado_der = x509.load_pem_x509_certificate(
        rutas["certificado_cliente"].read_bytes()
    ).public_bytes(
        serialization.Encoding.DER
    )
    ruta_db = tmp_path / "rf1.sqlite3"
    inicializar_base_datos(ruta_db)

    assert buscar_emparejamiento_certificado(
        certificado_der,
        ruta_base_datos=ruta_db,
    ) is None
    print("[IDENTIDAD] Certificado válido de la CA pero no emparejado: rechazado")
