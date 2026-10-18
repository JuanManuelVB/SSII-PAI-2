"""Persistencia de desafíos de acceso y sesiones RF2 en SQLite.

Los tokens se generan aleatoriamente y nunca se almacenan en claro.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO, conectar_base_datos, inicializar_base_datos

DURACION_DESAFIO_SEG = 90
DURACION_SESION_MIN = 30


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


def _marca(fecha: datetime) -> str:
    return fecha.isoformat()


def _hash_token(valor: str) -> str:
    return hashlib.sha256(valor.encode("utf-8")).hexdigest()


def inicializar_sesiones(ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> None:
    inicializar_base_datos(ruta)
    with conectar_base_datos(ruta) as conexion:
        conexion.executescript("""
            CREATE TABLE IF NOT EXISTS login_challenges (
                nonce TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                device_id TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL REFERENCES users(username),
                device_id TEXT NOT NULL REFERENCES device_pairings(device_id),
                certificate_serial TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
        """)


def crear_desafio(username: str, device_id: str, ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> tuple[str, str]:
    inicializar_sesiones(ruta)
    nonce = secrets.token_urlsafe(32)
    fecha_expiracion = _marca(_ahora() + timedelta(seconds=DURACION_DESAFIO_SEG))
    with conectar_base_datos(ruta) as conexion:
        conexion.execute("DELETE FROM login_challenges WHERE expires_at <= ?", (_marca(_ahora()),))
        conexion.execute(
            "INSERT INTO login_challenges(nonce,username,device_id,expires_at) VALUES(?,?,?,?)",
            (nonce, username, device_id, fecha_expiracion),
        )
    return nonce, fecha_expiracion


def consumir_desafio(nonce: str, username: str, device_id: str, ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> bool:
    """Un desafío solo puede utilizarse una vez, incluso si el login falla."""
    with conectar_base_datos(ruta) as conexion:
        resultado = conexion.execute(
            "DELETE FROM login_challenges WHERE nonce=? AND username=? AND device_id=? AND expires_at > ?",
            (nonce, username, device_id, _marca(_ahora())),
        )
    return resultado.rowcount == 1


def crear_sesion(
    username: str,
    device_id: str,
    certificate_serial: str,
    ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO,
) -> tuple[str, str]:
    """Devuelve el token al cliente; SQLite solo guarda su hash."""
    token = secrets.token_urlsafe(32)
    momento = _ahora()
    expiracion = _marca(momento + timedelta(minutes=DURACION_SESION_MIN))
    with conectar_base_datos(ruta) as conexion:
        conexion.execute(
            """INSERT INTO sessions
            (token_hash, username, device_id, certificate_serial, created_at, expires_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL)""",
            (_hash_token(token), username, device_id, certificate_serial, _marca(momento), expiracion),
        )
    return token, expiracion


def validar_sesion(token: str, ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> dict[str, str] | None:
    """Una sesión deja de servir si se bloquea usuario o se revoca dispositivo."""
    if not token:
        return None
    with conectar_base_datos(ruta) as conexion:
        fila = conexion.execute(
            """SELECT s.username, s.device_id, s.expires_at, u.role, s.certificate_serial, d.public_key_fingerprint
            FROM sessions s
            JOIN users u ON u.username = s.username
            JOIN device_pairings d ON d.device_id = s.device_id
            WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at > ?
            AND u.status = 'active' AND d.status = 'active'
            AND d.username = s.username AND d.certificate_serial = s.certificate_serial""",
            (_hash_token(token), _marca(_ahora())),
        ).fetchone()
    return dict(fila) if fila is not None else None


def revocar_token(token: str, ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> bool:
    """Revoca exclusivamente una sesión RF2, sin depender de OpenVPN REST."""
    if not token:
        return False
    with conectar_base_datos(ruta) as conexion:
        resultado = conexion.execute(
            "UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
            (_marca(_ahora()), _hash_token(token)),
        )
    return resultado.rowcount == 1
