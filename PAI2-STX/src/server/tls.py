"""Creación del contexto TLS 1.3 del gateway VPN."""

from __future__ import annotations

import hashlib
import ssl
import sqlite3
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from src.common.base_datos import conectar_base_datos
from src.common.config_tls import (
    RUTA_CERTIFICADO_CA,
    RUTA_CERTIFICADO_SERVIDOR,
    RUTA_CLAVE_SERVIDOR,
)


def _comprobar_archivos_tls(
    ruta_ca: Path,
    ruta_certificado: Path,
    ruta_clave: Path,
) -> None:
    """Comprueba que el material necesario existe antes de configurar TLS."""
    archivos = {
        "certificado de la CA": ruta_ca,
        "certificado del servidor": ruta_certificado,
        "clave privada del servidor": ruta_clave,
    }
    faltantes = [nombre for nombre, ruta in archivos.items() if not ruta.is_file()]
    if faltantes:
        detalle = ", ".join(faltantes)
        raise FileNotFoundError(
            f"No se encuentra el material TLS requerido: {detalle}"
        )


def crear_contexto_tls_servidor(
    *,
    ruta_ca: Path = RUTA_CERTIFICADO_CA,
    ruta_certificado: Path = RUTA_CERTIFICADO_SERVIDOR,
    ruta_clave: Path = RUTA_CLAVE_SERVIDOR,
) -> ssl.SSLContext:
    """Crea un contexto de servidor TLS 1.3 con certificados cliente obligatorios.

    La comprobación criptográfica del certificado cliente la realiza OpenSSL
    usando la CA indicada. La asociación posterior con ``device_pairings`` y
    la comprobación de la CRL se añadirán en la siguiente fase.
    """
    _comprobar_archivos_tls(ruta_ca, ruta_certificado, ruta_clave)

    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_3
    contexto.maximum_version = ssl.TLSVersion.TLSv1_3
    contexto.load_cert_chain(
        certfile=str(ruta_certificado),
        keyfile=str(ruta_clave),
    )
    contexto.load_verify_locations(cafile=str(ruta_ca))
    contexto.verify_mode = ssl.CERT_REQUIRED
    contexto.check_hostname = False
    return contexto


def obtener_huella_clave_certificado(certificado_der: bytes) -> str:
    """Calcula la huella de la clave pública contenida en un certificado DER.

    RF1 guarda esta misma huella en ``device_pairings``. Se calcula sobre la
    clave pública y no sobre el certificado completo para que la identidad
    criptográfica sobreviva a una reemisión del certificado con la misma clave.
    """
    try:
        certificado = x509.load_der_x509_certificate(certificado_der)
    except ValueError as exc:
        raise ValueError("El certificado cliente no contiene un DER válido") from exc

    clave_publica_der = certificado.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(clave_publica_der).hexdigest()


def buscar_emparejamiento_certificado(
    certificado_der: bytes,
    *,
    ruta_base_datos: Path,
) -> sqlite3.Row | None:
    """Busca un certificado en los emparejamientos activos de RF1.

    ``SSLContext`` ya debe haber validado la firma, la vigencia y la CA.
    Esta consulta añade la autorización de la aplicación: un certificado
    criptográficamente válido pero no emparejado no puede usar el gateway.
    """
    huella = obtener_huella_clave_certificado(certificado_der)
    with conectar_base_datos(ruta_base_datos) as conexion:
        return conexion.execute(
            """
            SELECT device_id, username, public_key_fingerprint,
                   certificate_serial, certificate_path, status
            FROM device_pairings
            WHERE public_key_fingerprint = ?
              AND status = 'active'
            """,
            (huella,),
        ).fetchone()
