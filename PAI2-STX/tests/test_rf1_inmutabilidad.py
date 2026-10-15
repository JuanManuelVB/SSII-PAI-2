"""Pruebas de RF1: inmutabilidad de identidades y claves públicas registradas."""

from __future__ import annotations

import sqlite3

import pytest

from pki.scripts import pki
from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.rf5 import gestion

HUELLA = "a" * 64


def _base_con_emparejamiento(ruta):
    """Crea un usuario manual con un dispositivo activo."""
    inicializar_base_datos(ruta)
    with conectar_base_datos(ruta) as conexion:
        conexion.execute(
            """
            INSERT INTO users
            (username, password_hash, role, status, origin, created_at, updated_at)
            VALUES ('pdi001', 'scrypt$00$00', 'PDI', 'active', 'MANUAL', 't', 't')
            """
        )
        conexion.execute(
            """
            INSERT INTO device_pairings
            (device_id, username, public_key_fingerprint, certificate_serial,
             certificate_path, created_at, status)
            VALUES ('dev-001', 'pdi001', ?, '1001', 'dev-001.crt', 't', 'active')
            """,
            (HUELLA,),
        )


def _emparejamiento(ruta, device_id="dev-001"):
    with conectar_base_datos(ruta) as conexion:
        return conexion.execute(
            "SELECT * FROM device_pairings WHERE device_id = ?", (device_id,)
        ).fetchone()


@pytest.mark.parametrize(
    ("columna", "valor"),
    [
        ("public_key_fingerprint", "b" * 64),
        ("certificate_serial", "2002"),
        ("username", "otro"),
        ("device_id", "dev-999"),
    ],
)
def test_no_se_puede_modificar_identidad_ni_clave_publica(tmp_path, columna, valor):
    """Un UPDATE directo sobre la identidad registrada es rechazado por SQLite."""
    ruta = tmp_path / "rf1.sqlite3"
    _base_con_emparejamiento(ruta)

    with pytest.raises(sqlite3.IntegrityError, match="RF1"):
        with conectar_base_datos(ruta) as conexion:
            conexion.execute(
                f"UPDATE device_pairings SET {columna} = ? WHERE device_id = 'dev-001'",
                (valor,),
            )

    assert _emparejamiento(ruta)["public_key_fingerprint"] == HUELLA
    print(f"[RF1] UPDATE de {columna} rechazado: el registro es inmutable")


def test_revocar_se_permite_pero_reactivar_no(tmp_path):
    """El único cambio de estado válido es active -> revoked."""
    ruta = tmp_path / "rf1.sqlite3"
    _base_con_emparejamiento(ruta)

    with conectar_base_datos(ruta) as conexion:
        conexion.execute(
            "UPDATE device_pairings SET status = 'revoked' WHERE device_id = 'dev-001'"
        )
    assert _emparejamiento(ruta)["status"] == "revoked"

    with pytest.raises(sqlite3.IntegrityError, match="RF1"):
        with conectar_base_datos(ruta) as conexion:
            conexion.execute(
                "UPDATE device_pairings SET status = 'active' WHERE device_id = 'dev-001'"
            )
    assert _emparejamiento(ruta)["status"] == "revoked"
    print("[RF1] Revocación permitida; reactivación de un dispositivo revocado rechazada")


def test_emparejamiento_no_se_puede_borrar(tmp_path):
    """Borrar y volver a insertar permitiría saltarse la inmutabilidad."""
    ruta = tmp_path / "rf1.sqlite3"
    _base_con_emparejamiento(ruta)

    with pytest.raises(sqlite3.IntegrityError, match="RF1"):
        with conectar_base_datos(ruta) as conexion:
            conexion.execute("DELETE FROM device_pairings WHERE device_id = 'dev-001'")
    assert _emparejamiento(ruta) is not None
    print("[RF1] DELETE de un emparejamiento rechazado")


def test_username_inmutable_y_contrasena_modificable(tmp_path):
    """La identidad del usuario no cambia; la contraseña sí puede rotarse."""
    ruta = tmp_path / "rf1.sqlite3"
    _base_con_emparejamiento(ruta)

    with pytest.raises(sqlite3.IntegrityError, match="RF1"):
        with conectar_base_datos(ruta) as conexion:
            conexion.execute("UPDATE users SET username = 'pdi999' WHERE username = 'pdi001'")

    with conectar_base_datos(ruta) as conexion:
        conexion.execute(
            "UPDATE users SET password_hash = 'scrypt$11$11' WHERE username = 'pdi001'"
        )
    print("[RF1] username inmutable; cambio de contraseña permitido")


def test_restricciones_se_aplican_a_bases_existentes(tmp_path):
    """Una base creada antes de esta corrección queda protegida al inicializar."""
    ruta = tmp_path / "antigua.sqlite3"
    _base_con_emparejamiento(ruta)
    with conectar_base_datos(ruta) as conexion:
        for nombre in (
            "rf1_emparejamiento_inmutable",
            "rf1_emparejamiento_no_reactivable",
            "rf1_emparejamiento_no_borrable",
            "rf1_usuario_identidad_inmutable",
        ):
            conexion.execute(f"DROP TRIGGER {nombre}")
        conexion.execute(
            "UPDATE device_pairings SET certificate_serial = '3003' WHERE device_id = 'dev-001'"
        )

    inicializar_base_datos(ruta)

    with pytest.raises(sqlite3.IntegrityError, match="RF1"):
        with conectar_base_datos(ruta) as conexion:
            conexion.execute(
                "UPDATE device_pairings SET certificate_serial = '4004' WHERE device_id = 'dev-001'"
            )
    print("[RF1] Base previa sin disparadores protegida tras inicializar_base_datos")


# ------------------------------------------------------------------ RF5 + RF1


@pytest.fixture
def entorno_rf5(tmp_path):
    """Tres usuarios RF5 con certificados emitidos por una CA temporal."""
    pki.crear_ca(tmp_path)
    ruta_db = tmp_path / "data" / "rf5.sqlite3"
    gestion.precargar_usuarios(
        3,
        ruta_base_datos=ruta_db,
        ruta_credenciales=tmp_path / "privado" / "credenciales.csv",
    )
    args = {
        "ruta_base_datos": ruta_db,
        "directorio_destino": tmp_path / "pki" / "clients" / "rf5",
        "ruta_ca_cert": tmp_path / "pki" / "ca" / "ca.crt",
        "ruta_ca_key": tmp_path / "pki" / "ca" / "ca.key",
    }
    assert gestion.emitir_certificados(**args)["emitidos"] == 3
    return args


def test_rf5_no_reactiva_un_dispositivo_revocado(entorno_rf5):
    """Repetir la emisión no devuelve a 'active' un dispositivo revocado."""
    ruta_db = entorno_rf5["ruta_base_datos"]
    device_id = "rf5-pdi-001-dev01"
    previo = _emparejamiento(ruta_db, device_id)
    with conectar_base_datos(ruta_db) as conexion:
        conexion.execute(
            "UPDATE device_pairings SET status = 'revoked' WHERE device_id = ?",
            (device_id,),
        )

    resultado = gestion.emitir_certificados(**entorno_rf5)

    actual = _emparejamiento(ruta_db, device_id)
    assert resultado["omitidos_revocados"] == 1
    assert resultado["reutilizados"] == 2
    assert actual["status"] == "revoked"
    assert actual["public_key_fingerprint"] == previo["public_key_fingerprint"]
    print("[RF1/RF5] Dispositivo revocado omitido; no se reactiva")


def test_rf5_no_sustituye_la_clave_si_falta_el_material(entorno_rf5):
    """Sin .crt/.key no se genera una clave nueva para un dispositivo emparejado."""
    ruta_db = entorno_rf5["ruta_base_datos"]
    destino = entorno_rf5["directorio_destino"]
    device_id = "rf5-pdi-001-dev01"
    previo = _emparejamiento(ruta_db, device_id)
    (destino / "rf5_pdi_001.crt").unlink()
    (destino / "rf5_pdi_001.key").unlink()

    with pytest.raises(gestion.ErrorRF5, match="re-emisión"):
        gestion.emitir_certificados(**entorno_rf5)

    assert _emparejamiento(ruta_db, device_id)["public_key_fingerprint"] == (
        previo["public_key_fingerprint"]
    )
    assert not (destino / "rf5_pdi_001.key").exists()
    print("[RF1/RF5] Material ausente: no se genera ni registra una clave nueva")


def test_rf5_rechaza_material_que_no_coincide_con_el_registro(entorno_rf5):
    """Un certificado local distinto del registrado no se acepta ni se guarda."""
    ruta_db = entorno_rf5["ruta_base_datos"]
    destino = entorno_rf5["directorio_destino"]
    previo = _emparejamiento(ruta_db, "rf5-pdi-001-dev01")
    for extension in ("crt", "key"):
        (destino / f"rf5_pdi_001.{extension}").write_bytes(
            (destino / f"rf5_pas_001.{extension}").read_bytes()
        )

    with pytest.raises(gestion.ErrorRF5, match="no coincide"):
        gestion.emitir_certificados(**entorno_rf5)

    assert _emparejamiento(ruta_db, "rf5-pdi-001-dev01")["public_key_fingerprint"] == (
        previo["public_key_fingerprint"]
    )
    print("[RF1/RF5] Material local distinto del registrado: rechazado")
