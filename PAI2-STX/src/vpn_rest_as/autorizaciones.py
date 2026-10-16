"""Autorizaciones temporales vinculadas a sesiones RF2; nunca guarda tokens.

Esta tabla es un registro de concesiones, NO sustituye al control de acceso
propio de Access Server. Access Server debe tener deny=true por defecto en los
usuarios de laboratorio y denegar logins que no pasen por RF2.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO, conectar_base_datos
from src.rf2.sesiones import _hash_token, validar_sesion


def inicializar(ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> None:
    with conectar_base_datos(ruta) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS vpn_grants (
            token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
            device_id TEXT NOT NULL, granted_at TEXT NOT NULL,
            disabled_at TEXT
        )''')


def autorizacion_vigente(token: str, ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> bool:
    if validar_sesion(token, ruta) is None:
        return False
    inicializar(ruta)
    with conectar_base_datos(ruta) as conn:
        row = conn.execute(
            "SELECT 1 FROM vpn_grants WHERE token_hash=? AND disabled_at IS NULL",
            (_hash_token(token),)
        ).fetchone()
    return row is not None


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
