"""Utilidades comunes para proteger las contraseñas de los usuarios."""

from __future__ import annotations

import hashlib
import secrets

# Estos parámetros se mantienen centralizados para que RF1, RF5 y el futuro
# login utilicen exactamente el mismo algoritmo y la misma configuración.
ALGORITMO_HASH = "scrypt"
PARAMETRO_N = 2**14
PARAMETRO_R = 8
PARAMETRO_P = 1
LONGITUD_SAL = 16


def crear_hash_contrasena(contrasena: str, sal: bytes | None = None) -> str:
    """Genera un hash scrypt con sal y devuelve un formato autocontenido.

    La sal no es secreta: se guarda junto al hash para poder verificar la
    contraseña más adelante. La contraseña original nunca se almacena.
    """
    if not contrasena:
        raise ValueError("La contraseña no puede estar vacía")

    sal_usada = sal if sal is not None else secrets.token_bytes(LONGITUD_SAL)
    resumen = hashlib.scrypt(
        contrasena.encode("utf-8"),
        salt=sal_usada,
        n=PARAMETRO_N,
        r=PARAMETRO_R,
        p=PARAMETRO_P,
    )
    return f"{ALGORITMO_HASH}${sal_usada.hex()}${resumen.hex()}"


def verificar_contrasena(contrasena: str, hash_almacenado: str) -> bool:
    """Comprueba una contraseña sin revelar información del hash válido."""
    try:
        algoritmo, sal_hex, resumen_hex = hash_almacenado.split("$")
        if algoritmo != ALGORITMO_HASH:
            return False

        hash_candidato = crear_hash_contrasena(
            contrasena,
            sal=bytes.fromhex(sal_hex),
        )
        hash_esperado = f"{ALGORITMO_HASH}${sal_hex}${resumen_hex}"
        return secrets.compare_digest(hash_candidato, hash_esperado)
    except (ValueError, TypeError):
        # Un hash corrupto se trata como una credencial no válida, sin
        # propagar detalles internos al usuario de la API.
        return False
