"""Autorizaciones temporales vinculadas a sesiones RF2; nunca guarda tokens.

Esta tabla es un registro de concesiones, NO sustituye al control de acceso
propio de Access Server. Access Server debe tener deny=true por defecto en los
usuarios de laboratorio y denegar logins que no pasen por RF2.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO, conectar_base_datos
from src.rf2.sesiones import _hash_token


def inicializar(ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> None:
    with conectar_base_datos(ruta) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS vpn_grants (
            token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
            device_id TEXT NOT NULL, granted_at TEXT NOT NULL,
            disabled_at TEXT
        )''')


def guardar_concesion(token: str, username: str, device_id: str,
                     ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> None:
    inicializar(ruta)
    now = datetime.now(timezone.utc).isoformat()
    with conectar_base_datos(ruta) as conn:
        conn.execute('''INSERT INTO vpn_grants(token_hash,username,device_id,granted_at,disabled_at)
                     VALUES(?,?,?,?,NULL)
                     ON CONFLICT(token_hash) DO UPDATE SET granted_at=excluded.granted_at,
                     disabled_at=NULL''', (_hash_token(token),username,device_id,now))


def bloquear_concesiones_usuario(username: str, ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> None:
    inicializar(ruta)
    now = datetime.now(timezone.utc).isoformat()
    with conectar_base_datos(ruta) as conn:
        conn.execute('''UPDATE vpn_grants SET disabled_at=?
                     WHERE username=? AND disabled_at IS NULL''', (now,username))
        # Invalidar el resto de tokens RF2 de la cuenta: ningún token antiguo
        # podrá reactivar una VPN después de logout.
        conn.execute('''UPDATE sessions SET revoked_at=?
                    WHERE username=? AND revoked_at IS NULL''', (now,username))


def hay_concesion_de_otro_dispositivo(username: str, device_id: str,
                                     ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> bool:
    """No permitir que dos dispositivos compartan la cuenta VPN userlogin."""
    from src.rf2.sesiones import inicializar_sesiones
    inicializar_sesiones(ruta)
    inicializar(ruta)
    ahora = datetime.now(timezone.utc).isoformat()
    with conectar_base_datos(ruta) as conn:
        fila = conn.execute("""SELECT 1 FROM vpn_grants g
            JOIN sessions s ON s.token_hash=g.token_hash
            WHERE g.username=? AND g.device_id<>? AND g.disabled_at IS NULL
              AND s.revoked_at IS NULL AND s.expires_at>? LIMIT 1""",
            (username, device_id, ahora)).fetchone()
    return fila is not None
