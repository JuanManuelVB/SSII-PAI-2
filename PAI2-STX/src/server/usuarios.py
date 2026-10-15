"""Comandos de terminal para administrar usuarios de RF1."""

from __future__ import annotations

import argparse
import getpass
import secrets
import sqlite3

from src.common.base_datos import (
    ahora,
    conectar_base_datos,
    inicializar_base_datos,
)
from src.common.seguridad import crear_hash_contrasena

from .app import _auditar

ROLES_VALIDOS = ("PDI", "PAS", "INVESTIGADOR")


def crear_usuario(nombre_usuario: str, rol: str) -> None:
    """Crea una cuenta activa solicitando la contraseña de forma segura."""
    if rol not in ROLES_VALIDOS:
        raise ValueError(f"El rol debe ser uno de: {', '.join(ROLES_VALIDOS)}")

    contrasena = getpass.getpass("Contraseña: ")
    confirmacion = getpass.getpass("Repita la contraseña: ")
    if len(contrasena) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres")
    if contrasena != confirmacion:
        raise ValueError("Las contraseñas no coinciden")

    marca_tiempo = ahora()
    sal = secrets.token_bytes(16)
    hash_contrasena = crear_hash_contrasena(contrasena, sal)
    inicializar_base_datos()
    try:
        with conectar_base_datos() as conexion:
            conexion.execute(
                """
                INSERT INTO users
                (username, password_hash, role, status, created_at, updated_at)
                VALUES (?, ?, ?, 'active', ?, ?)
                """,
                (nombre_usuario, hash_contrasena, rol, marca_tiempo, marca_tiempo),
            )
    except sqlite3.IntegrityError as exc:
        _auditar("user_creation_rejected", username=nombre_usuario, reason="duplicate_or_invalid")
        raise ValueError(f"El usuario '{nombre_usuario}' ya existe") from exc
    _auditar("user_created", username=nombre_usuario, role=rol)
    print(f"Usuario '{nombre_usuario}' creado correctamente.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Administración manual de usuarios RF1")
    subparsers = parser.add_subparsers(dest="comando", required=True)
    crear = subparsers.add_parser("crear", help="crear un usuario")
    crear.add_argument("username")
    crear.add_argument("role", choices=ROLES_VALIDOS)
    argumentos = parser.parse_args()
    if argumentos.comando == "crear":
        crear_usuario(argumentos.username, argumentos.role)


if __name__ == "__main__":
    main()
