"""RF2 — Autenticación en dos capas: certificado del dispositivo + credenciales.

Capa 1 (transporte): el handshake mTLS ha validado el certificado cliente
contra la CA corporativa. De él se obtiene la huella de su clave pública.
Capa 2 (aplicación): usuario y contraseña se verifican contra SQLite y se
comprueba que el certificado presentado pertenece a ese usuario y que el
dispositivo sigue activo en ``device_pairings``.

Solo se devuelve un ``ResultadoAutenticacion`` cuando ambas capas son válidas.
Cualquier otro caso lanza una subclase de ``ErrorAutenticacion``. Todas
comparten el mismo mensaje público para no revelar qué comprobación falló; el
motivo concreto queda en el atributo ``motivo`` para la auditoría (RS4).
"""

from __future__ import annotations

import secrets
from contextlib import closing
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO, conectar_base_datos
from src.common.seguridad import crear_hash_contrasena, verificar_contrasena
from src.server.identidad_certificado import normalizar_huella

MENSAJE_PUBLICO = "Autenticación rechazada"


class ErrorAutenticacion(Exception):
    """Rechazo de autenticación. El mensaje nunca incluye datos de la petición."""

    motivo = "authentication_failed"

    def __init__(self) -> None:
        super().__init__(MENSAJE_PUBLICO)


class HuellaInvalida(ErrorAutenticacion):
    motivo = "invalid_certificate_fingerprint"


class UsuarioInexistente(ErrorAutenticacion):
    motivo = "unknown_user"


class ContrasenaIncorrecta(ErrorAutenticacion):
    motivo = "invalid_password"


class UsuarioInactivo(ErrorAutenticacion):
    motivo = "inactive_user"


class CertificadoNoEmparejado(ErrorAutenticacion):
    motivo = "unpaired_certificate"


class CertificadoDeOtroUsuario(ErrorAutenticacion):
    motivo = "certificate_user_mismatch"


class DispositivoRevocado(ErrorAutenticacion):
    motivo = "revoked_device"


@dataclass(frozen=True)
class ResultadoAutenticacion:
    """Identidad autenticada que RF4 utilizará para abrir la sesión."""

    username: str
    role: str
    origin: str
    device_id: str
    certificate_serial: str


@lru_cache(maxsize=1)
def _hash_ficticio() -> str:
    """Hash scrypt de una contraseña aleatoria que nunca coincidirá.

    Se verifica contra él cuando el usuario no existe, para que la respuesta
    tarde lo mismo que con un usuario real y no permita enumerar cuentas.
    """
    return crear_hash_contrasena(secrets.token_urlsafe(32))


def autenticar_usuario(
    username: str,
    password: str,
    huella_certificado: str,
    *,
    ruta_base_datos: Path = RUTA_BASE_DATOS_POR_DEFECTO,
) -> ResultadoAutenticacion:
    """Autentica al usuario solo si credenciales y certificado son coherentes.

    ``huella_certificado`` debe proceder del certificado validado en el
    handshake mTLS (``huella_desde_conexion_tls``), nunca de datos enviados
    por el cliente.
    """
    try:
        huella = normalizar_huella(huella_certificado)
    except ValueError:
        raise HuellaInvalida() from None

    if not ruta_base_datos.is_file():
        # Un fallo de configuración no debe confundirse con credenciales
        # incorrectas ni crear una base vacía.
        raise FileNotFoundError("No se encuentra la base de datos de usuarios")

    if not isinstance(username, str) or not isinstance(password, str):
        verificar_contrasena("", _hash_ficticio())
        raise ContrasenaIncorrecta()

    with closing(conectar_base_datos(ruta_base_datos)) as conexion:
        usuario = conexion.execute(
            """
            SELECT username, password_hash, role, status, origin
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if usuario is None:
            verificar_contrasena(password, _hash_ficticio())
            raise UsuarioInexistente()
        if not verificar_contrasena(password, usuario["password_hash"]):
            raise ContrasenaIncorrecta()
        if usuario["status"] != "active":
            raise UsuarioInactivo()

        # Se busca sin filtrar por estado para distinguir "no emparejado"
        # de "revocado" en la auditoría. public_key_fingerprint es UNIQUE.
        dispositivo = conexion.execute(
            """
            SELECT device_id, username, certificate_serial, status
            FROM device_pairings
            WHERE public_key_fingerprint = ?
            """,
            (huella,),
        ).fetchone()

    if dispositivo is None:
        raise CertificadoNoEmparejado()
    if dispositivo["username"] != usuario["username"]:
        raise CertificadoDeOtroUsuario()
    if dispositivo["status"] != "active":
        raise DispositivoRevocado()

    return ResultadoAutenticacion(
        username=usuario["username"],
        role=usuario["role"],
        origin=usuario["origin"],
        device_id=dispositivo["device_id"],
        certificate_serial=dispositivo["certificate_serial"],
    )
