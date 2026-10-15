"""Adaptador entre la capa mTLS (RF1/RS1, ``src/server/tls.py``) y el login RF2.

Este módulo no reimplementa ninguna lógica TLS: el cálculo de la huella lo
realiza ``obtener_huella_clave_certificado`` del módulo TLS. Aquí solo se
obtiene el certificado ya validado por OpenSSL en el handshake y se normaliza
la huella que recibirá ``autenticar_usuario``.
"""

from __future__ import annotations

import re
import ssl

from src.server.tls import obtener_huella_clave_certificado

# SHA-256 en hexadecimal: 32 bytes -> 64 caracteres.
_PATRON_HUELLA = re.compile(r"[0-9a-f]{64}")


def normalizar_huella(huella: object) -> str:
    """Devuelve la huella en minúsculas o lanza ``ValueError`` si no es válida.

    La huella identifica la clave pública del dispositivo (SHA-256 sobre
    SubjectPublicKeyInfo en DER), que es el valor que RF1 y RF5 guardan en
    ``device_pairings.public_key_fingerprint``.
    """
    if not isinstance(huella, str):
        raise ValueError("La huella del certificado debe ser texto")
    normalizada = huella.lower()
    if not _PATRON_HUELLA.fullmatch(normalizada):
        raise ValueError("La huella del certificado no es un SHA-256 hexadecimal")
    return normalizada


def huella_desde_conexion_tls(conexion: ssl.SSLSocket | ssl.SSLObject) -> str:
    """Obtiene la huella del certificado cliente de una conexión mTLS ya negociada.

    El servidor debe usar el contexto de ``crear_contexto_tls_servidor`` (TLS 1.3
    y ``CERT_REQUIRED``), de modo que OpenSSL ya ha comprobado la firma de la CA
    y la vigencia antes de llegar aquí. Nunca debe aceptarse una huella enviada
    por el cliente en el cuerpo de la petición o en una cabecera HTTP.
    """
    certificado_der = conexion.getpeercert(binary_form=True)
    if not certificado_der:
        raise ValueError("La conexión TLS no presenta certificado cliente")
    return obtener_huella_clave_certificado(certificado_der)
