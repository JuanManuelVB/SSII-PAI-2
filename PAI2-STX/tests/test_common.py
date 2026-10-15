"""Pruebas aisladas de la capa común de seguridad y base de datos."""

import sqlite3

from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.common.seguridad import crear_hash_contrasena, verificar_contrasena


def test_hash_de_contrasena_se_verifica_sin_guardar_la_original():
    """El hash permite validar la contraseña correcta y rechaza otra."""
    hash_almacenado = crear_hash_contrasena("Una contraseña segura")

    assert "Una contraseña segura" not in hash_almacenado
    assert verificar_contrasena("Una contraseña segura", hash_almacenado)
    assert not verificar_contrasena("Contraseña incorrecta", hash_almacenado)


def test_base_de_datos_crea_el_esquema_comun(tmp_path):
    """El esquema contiene usuarios y emparejamientos en la misma SQLite."""
    ruta = tmp_path / "rf1.sqlite3"
    inicializar_base_datos(ruta)

    with conectar_base_datos(ruta) as conexion:
        tablas = {
            fila["name"]
            for fila in conexion.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        columnas_usuarios = {
            fila["name"]
            for fila in conexion.execute("PRAGMA table_info(users)")
        }

    assert {"users", "device_pairings"}.issubset(tablas)
    assert {"username", "password_hash", "role", "status", "origin"}.issubset(
        columnas_usuarios
    )
