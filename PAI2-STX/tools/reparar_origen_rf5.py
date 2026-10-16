"""Repara cuentas RF5 históricas con origin=MANUAL sin recrear usuarios.

Compara cada cuenta con el CSV privado RF5: nombre, perfil y contraseña
contra su hash scrypt. Si algo no cuadra, NO cambia SQLite.

Uso:
    py tools/reparar_origen_rf5.py
    py tools/reparar_origen_rf5.py --aplicar
"""
from __future__ import annotations

import argparse
import csv
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.common.seguridad import verificar_contrasena  # noqa: E402

DEFAULT_DB = ROOT / "data" / "rf1.sqlite3"
DEFAULT_CSV = ROOT / "pki" / "clients" / "rf5" / "credenciales.csv"
PREFIX_TO_ROLE = {"pdi": "PDI", "pas": "PAS", "inv": "INVESTIGADOR"}
EXACT_COLUMNS = {"username", "password", "role", "device_id"}
PATTERN = re.compile(r"^rf5_(pdi|pas|inv)_(\d{3,4})$")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Valida y recupera el origen RF5 de usuarios ya existentes en SQLite"
    )
    parser.add_argument("--aplicar", action="store_true", help="Crear backup y corregir origin")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--credenciales", type=Path, default=DEFAULT_CSV)
    args = parser.parse_args()
    db = args.db.resolve()
    csv_path = args.credenciales.resolve()

    if not db.is_file():
        parser.error(f"No existe SQLite: {db}. No se creara otra base de datos.")
    if not csv_path.is_file():
        parser.error(f"No existe CSV privado de RF5: {csv_path}.")

    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        lector = csv.DictReader(f)
        if set(lector.fieldnames or []) != EXACT_COLUMNS:
            parser.error("CSV incompatible. Se esperan username, password, role y device_id.")
        registros = list(lector)

    if not registros or len({r["username"] for r in registros}) != len(registros):
        parser.error("CSV vacio o con nombres duplicados.")

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        if not {"username", "password_hash", "role", "origin"}.issubset(cols):
            parser.error("La tabla users no contiene las columnas necesarias.")

        pendientes = []
        existentes = 0
        for cred in registros:
            nombre = cred["username"]
            match = PATTERN.fullmatch(nombre)
            if not match:
                parser.error(f"Nombre no reconocido: {nombre}. No se ha cambiado nada.")
            expected_role = PREFIX_TO_ROLE[match.group(1)]
            if cred["role"].upper() != expected_role:
                parser.error(f"Rol del CSV incompatible para {nombre}.")
            expected_device = f"rf5-{match.group(1)}-{match.group(2)}-dev01"
            if cred["device_id"] != expected_device:
                parser.error(f"Dispositivo del CSV incompatible para {nombre}.")
            user = conn.execute(
                "SELECT username,role,origin,password_hash FROM users WHERE username = ?",
                (nombre,),
            ).fetchone()
            if user is None:
                parser.error(f"El usuario {nombre} no existe en SQLite.")
            if user["role"] != expected_role:
                parser.error(f"Rol SQLite incompatible para {nombre}.")
            if not verificar_contrasena(cred["password"], user["password_hash"]):
                parser.error(f"La contraseña de {nombre} no coincide con el hash SQLite.")
            if user["origin"] == "RF5":
                existentes += 1
            elif user["origin"] == "MANUAL":
                pendientes.append((nombre, expected_role, user["password_hash"]))
            else:
                parser.error(f"Origen incompatible ({user['origin']}) para {nombre}.")

        print(f"Cuentas del CSV verificadas con hash scrypt: {len(registros)}")
        print(f"Ya identificadas como RF5: {existentes}")
        print(f"Cuentas recuperables (MANUAL -> RF5): {len(pendientes)}")
        if not args.aplicar:
            print("Modo comprobacion: SQLite NO se ha modificado.")
            print("Si los resultados son correctos, ejecuta con --aplicar.")
            return 0
        if not pendientes:
            print("No hay ninguna cuenta que reparar.")
            return 0

        # La API de backup de SQLite crea una copia consistente antes del UPDATE.
        marca = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = db.with_name(f"{db.stem}.backup-antes-rf5-{marca}{db.suffix}")
        if backup.exists():
            parser.error(f"Ya existe la ruta de backup: {backup}")
        with sqlite3.connect(str(backup)) as copia:
            conn.backup(copia)
        print(f"Copia de seguridad: {backup}")

        conn.execute("BEGIN IMMEDIATE")
        for username, role, password_hash in pendientes:
            result = conn.execute(
                """UPDATE users SET origin = 'RF5'
                   WHERE username = ? AND role = ? AND password_hash = ? AND origin = 'MANUAL'""",
                (username, role, password_hash),
            )
            if result.rowcount != 1:
                raise RuntimeError(f"La cuenta {username} ha cambiado durante la reparacion")
        conn.commit()
        print(f"REPARACION COMPLETA: {len(pendientes)} cuentas marcadas como RF5.")
        print("Los hashes, contraseñas, roles y dispositivos no se han modificado.")
        return 0
    except (sqlite3.Error, RuntimeError) as exc:
        conn.rollback()
        print(f"ERROR: {exc}. Se ha revertido la transaccion.", file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
