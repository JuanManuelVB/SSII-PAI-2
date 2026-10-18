"""Conexión y esquema SQLite compartidos por RF1 y RF5."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
RUTA_BASE_DATOS_POR_DEFECTO = RAIZ_PROYECTO / "data" / "rf1.sqlite3"


def ahora() -> str:
    """Devuelve una marca temporal UTC en formato ISO-8601."""
    return datetime.now(timezone.utc).isoformat()


def conectar_base_datos(
    ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO,
) -> sqlite3.Connection:
    """Abre SQLite con filas consultables por nombre y claves foráneas activas."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(ruta)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON")
    return conexion


def inicializar_base_datos(
    ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO,
) -> None:
    """Crea el esquema común sin borrar datos existentes.

    La columna ``origin`` distingue cuentas manuales de cuentas generadas por
    RF5. Se añade mediante una migración pequeña para no romper bases creadas
    con la versión anterior de RF1.
    """
    with conectar_base_datos(ruta) as conexion:
        conexion.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('PDI', 'PAS', 'INVESTIGADOR')),
                status TEXT NOT NULL CHECK(status IN ('active', 'blocked', 'revoked')),
                origin TEXT NOT NULL DEFAULT 'MANUAL',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conexion.execute(
            """
            CREATE TABLE IF NOT EXISTS device_pairings (
                device_id TEXT PRIMARY KEY,
                username TEXT NOT NULL REFERENCES users(username),
                public_key_fingerprint TEXT NOT NULL UNIQUE,
                certificate_serial TEXT NOT NULL UNIQUE,
                certificate_path TEXT,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('active', 'revoked'))
            )
            """
        )

        columnas = {
            fila["name"]
            for fila in conexion.execute("PRAGMA table_info(users)").fetchall()
        }
        if "origin" not in columnas:
            conexion.execute(
                "ALTER TABLE users ADD COLUMN origin TEXT NOT NULL DEFAULT 'MANUAL'"
            )

        columnas_dispositivos = {
            fila["name"]
            for fila in conexion.execute("PRAGMA table_info(device_pairings)")
        }
        if "certificate_path" not in columnas_dispositivos:
            conexion.execute(
                "ALTER TABLE device_pairings ADD COLUMN certificate_path TEXT"
            )

        # RF1: un emparejamiento no se modifica por UPDATE. Para sustituir
        # una clave se revoca el dispositivo y se crea un emparejamiento nuevo.
        conexion.execute("""
            CREATE TRIGGER IF NOT EXISTS rf1_pairing_immutable
            BEFORE UPDATE OF username, public_key_fingerprint, certificate_serial
            ON device_pairings
            WHEN NEW.username != OLD.username OR
                 NEW.public_key_fingerprint != OLD.public_key_fingerprint OR
                 NEW.certificate_serial != OLD.certificate_serial
            BEGIN SELECT RAISE(ABORT, 'RF1: requiere revocación y nueva emisión'); END
        """)
        conexion.execute("""
            CREATE TRIGGER IF NOT EXISTS rf1_username_immutable
            BEFORE UPDATE OF username ON users
            WHEN NEW.username != OLD.username
            BEGIN SELECT RAISE(ABORT, 'RF1: identidad inmutable'); END
        """)
