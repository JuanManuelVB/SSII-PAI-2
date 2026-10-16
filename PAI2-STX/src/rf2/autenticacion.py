"""Validación de credenciales y prueba criptográfica del certificado BYOD.

El proceso TLS del gateway exige mTLS; además el login comprueba posesión
individual de la clave correspondiente al emparejamiento guardado por RF1.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO, conectar_base_datos
from src.common.config_tls import RUTA_CERTIFICADO_CA
from src.common.seguridad import verificar_contrasena
from src.rf2.sesiones import consumir_desafio


class AutenticacionRechazada(ValueError):
    """No se detalla al cliente qué credencial falló."""


def mensaje_a_firmar(nonce: str, username: str, device_id: str) -> bytes:
    return f"PAI2-RF2-LOGIN\n{nonce}\n{username}\n{device_id}".encode("utf-8")


def _verificar_firma_emisor(certificado: x509.Certificate, ca: x509.Certificate) -> None:
    clave = ca.public_key()
    if isinstance(clave, rsa.RSAPublicKey):
        clave.verify(certificado.signature, certificado.tbs_certificate_bytes,
                     padding.PKCS1v15(), certificado.signature_hash_algorithm)
    elif isinstance(clave, ec.EllipticCurvePublicKey):
        clave.verify(certificado.signature, certificado.tbs_certificate_bytes,
                     ec.ECDSA(certificado.signature_hash_algorithm))
    else:
        raise AutenticacionRechazada("certificado no autorizado")


def _verificar_certificado(certificado_pem: str, ruta_ca: Path, ruta_revocados: Path | None) -> x509.Certificate:
    try:
        cert = x509.load_pem_x509_certificate(certificado_pem.encode("ascii"))
        ca = x509.load_pem_x509_certificate(ruta_ca.read_bytes())
        momento = datetime.now(timezone.utc)
        if not (cert.not_valid_before_utc <= momento < cert.not_valid_after_utc):
            raise AutenticacionRechazada("certificado no autorizado")
        if not (ca.not_valid_before_utc <= momento < ca.not_valid_after_utc):
            raise AutenticacionRechazada("certificado no autorizado")
        if cert.issuer != ca.subject:
            raise AutenticacionRechazada("certificado no autorizado")
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise AutenticacionRechazada("certificado no autorizado")
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise AutenticacionRechazada("certificado no autorizado")
        if ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise AutenticacionRechazada("certificado no autorizado")
        _verificar_firma_emisor(cert, ca)
        if ruta_revocados is not None and ruta_revocados.exists():
            datos = json.loads(ruta_revocados.read_text(encoding="utf-8"))
            if not isinstance(datos, list):
                raise AutenticacionRechazada("certificado no autorizado")
            if any(str(item.get("serial")) == str(cert.serial_number) for item in datos):
                raise AutenticacionRechazada("certificado no autorizado")
        return cert
    except (ValueError, OSError, UnicodeError, InvalidSignature, x509.ExtensionNotFound,
            json.JSONDecodeError, TypeError, KeyError) as exc:
        raise AutenticacionRechazada("certificado no autorizado") from exc


def autenticar(
    *, username: str, password: str, device_id: str, nonce: str,
    certificate: str, signature: str,
    ruta_base_datos: Path = RUTA_BASE_DATOS_POR_DEFECTO,
    ruta_ca: Path = RUTA_CERTIFICADO_CA,
    ruta_revocados: Path | None = None,
) -> str:
    """Devuelve el nº de serie solo cuando ambos factores están validados."""
    if not consumir_desafio(nonce, username, device_id, ruta_base_datos):
        raise AutenticacionRechazada("credenciales o dispositivo no autorizados")

    cert = _verificar_certificado(certificate, ruta_ca, ruta_revocados)
    try:
        firma_bytes = base64.b64decode(signature, validate=True)
        clave = cert.public_key()
        mensaje = mensaje_a_firmar(nonce, username, device_id)
        if isinstance(clave, rsa.RSAPublicKey):
            clave.verify(firma_bytes, mensaje, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(clave, ec.EllipticCurvePublicKey):
            clave.verify(firma_bytes, mensaje, ec.ECDSA(hashes.SHA256()))
        else:
            raise AutenticacionRechazada("credenciales o dispositivo no autorizados")
    except (binascii.Error, InvalidSignature, ValueError) as exc:
        raise AutenticacionRechazada("credenciales o dispositivo no autorizados") from exc

    clave_publica_der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    huella = hashlib.sha256(clave_publica_der).hexdigest()
    with conectar_base_datos(ruta_base_datos) as conexion:
        fila = conexion.execute(
            """SELECT u.password_hash FROM users u
            JOIN device_pairings d ON d.username = u.username
            WHERE u.username=? AND u.status='active' AND d.device_id=?
            AND d.status='active' AND d.public_key_fingerprint=? AND d.certificate_serial=?""",
            (username, device_id, huella, str(cert.serial_number)),
        ).fetchone()
    if fila is None or not verificar_contrasena(password, fila["password_hash"]):
        raise AutenticacionRechazada("credenciales o dispositivo no autorizados")
    return str(cert.serial_number)
