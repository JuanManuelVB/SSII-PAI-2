"""Pruebas de RF5 sobre una base SQLite temporal."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.common.seguridad import crear_hash_contrasena, verificar_contrasena
from src.rf5 import gestion


def rutas(tmp_path):
    return {
        "ruta_base_datos": tmp_path / "data" / "rf5.sqlite3",
        "ruta_credenciales": tmp_path / "pki" / "rf5" / "credenciales.csv",
    }


def _usuarios(ruta):
    with conectar_base_datos(ruta) as conexion:
        return conexion.execute(
            "SELECT * FROM users ORDER BY username"
        ).fetchall()


def test_precarga_3_roles_guarda_hashes_y_no_password_plana(tmp_path):
    parametros = rutas(tmp_path)
    resultado = gestion.precargar_usuarios(3, **parametros)
    usuarios = _usuarios(parametros["ruta_base_datos"])
    credenciales = gestion._leer_credenciales(parametros["ruta_credenciales"])

    assert resultado["nuevos"] == 3
    assert {usuario["role"] for usuario in usuarios} == {"PDI", "PAS", "INVESTIGADOR"}
    assert all(usuario["origin"] == "RF5" for usuario in usuarios)
    assert len(credenciales) == 3
    texto_db = parametros["ruta_base_datos"].read_bytes()
    for cuenta in credenciales:
        usuario = next(u for u in usuarios if u["username"] == cuenta["username"])
        assert usuario["password_hash"].startswith("scrypt$")
        assert verificar_contrasena(cuenta["password"], usuario["password_hash"])
        assert cuenta["password"].encode() not in texto_db


def test_consulta_de_perfil_activo_y_sin_datos_sensibles(tmp_path):
    parametros = rutas(tmp_path)
    gestion.precargar_usuarios(3, **parametros)
    ruta = parametros["ruta_base_datos"]
    assert gestion.consultar_perfil("rf5_pas_001", ruta) == {
        "username": "rf5_pas_001",
        "role": "PAS",
        "device_id": "",
        "certificate_serial": "",
        "certificate_status": "pending",
    }
    with conectar_base_datos(ruta) as conexion:
        conexion.execute(
            "UPDATE users SET status = 'revoked' WHERE username = ?",
            ("rf5_pas_001",),
        )
    assert gestion.consultar_perfil("rf5_pas_001", ruta) is None


def test_repetir_precarga_es_idempotente_y_respeta_usuario_manual(tmp_path):
    parametros = rutas(tmp_path)
    ruta = parametros["ruta_base_datos"]
    inicializar_base_datos(ruta)
    with conectar_base_datos(ruta) as conexion:
        marca = gestion.ahora()
        conexion.execute(
            """
            INSERT INTO users
            (username, password_hash, role, status, origin, created_at, updated_at)
            VALUES (?, ?, 'PDI', 'active', 'MANUAL', ?, ?)
            """,
            ("rf5_pdi_001", crear_hash_contrasena("manual"), marca, marca),
        )

    with pytest.raises(gestion.ErrorRF5, match="Colisión"):
        gestion.precargar_usuarios(3, **parametros)
    with conectar_base_datos(ruta) as conexion:
        manual = conexion.execute(
            "SELECT origin, password_hash FROM users WHERE username = ?",
            ("rf5_pdi_001",),
        ).fetchone()
    assert manual["origin"] == "MANUAL"
    assert verificar_contrasena("manual", manual["password_hash"])


def test_300_usuarios_repartidos_y_sin_duplicados(tmp_path):
    parametros = rutas(tmp_path)
    assert gestion.precargar_usuarios(300, **parametros)["nuevos"] == 300
    resumen = gestion.resumen_usuarios(parametros["ruta_base_datos"])
    assert resumen["por_rol"] == {"PDI": 100, "PAS": 100, "INVESTIGADOR": 100}
    assert resumen["total_rf5"] == 300
    assert gestion.precargar_usuarios(300, **parametros)["nuevos"] == 0


def _ca_temporal(tmp_path):
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA-Prueba-RF5")])
    ahora = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nombre).issuer_name(nombre).public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(days=1))
        .not_valid_after(ahora + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(clave, hashes.SHA256())
    )
    ruta_cert, ruta_clave = tmp_path / "ca.crt", tmp_path / "ca.key"
    ruta_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ruta_clave.write_bytes(
        clave.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ruta_cert, ruta_clave


def test_certificados_emitidos_y_reutilizados_sin_sustituir_claves(tmp_path):
    parametros = rutas(tmp_path)
    gestion.precargar_usuarios(3, **parametros)
    cert_ca, clave_ca = _ca_temporal(tmp_path)
    destino = tmp_path / "pki" / "rf5"
    args = {
        "ruta_base_datos": parametros["ruta_base_datos"],
        "directorio_destino": destino,
        "ruta_ca_cert": cert_ca,
        "ruta_ca_key": clave_ca,
    }
    assert gestion.emitir_certificados(**args) == {
        "emitidos": 3, "reutilizados": 0, "total_procesados": 3
    }
    clave = destino / "rf5_pdi_001.key"
    previo = clave.read_bytes()
    assert gestion.resumen_usuarios(args["ruta_base_datos"])["certificados_emitidos"] == 3
    assert gestion.emitir_certificados(**args) == {
        "emitidos": 0, "reutilizados": 3, "total_procesados": 3
    }
    assert clave.read_bytes() == previo
    assert gestion.consultar_perfil("rf5_pdi_001", args["ruta_base_datos"])["certificate_status"] == "issued"


def test_no_emite_una_ca_inexistente_ni_altera_la_base(tmp_path):
    parametros = rutas(tmp_path)
    gestion.precargar_usuarios(3, **parametros)
    antes = parametros["ruta_base_datos"].read_bytes()
    with pytest.raises(gestion.ErrorRF5, match="Falta la CA"):
        gestion.emitir_certificados(
            ruta_base_datos=parametros["ruta_base_datos"],
            directorio_destino=tmp_path / "clientes",
            ruta_ca_cert=tmp_path / "ca-no-existe.crt",
            ruta_ca_key=tmp_path / "ca-no-existe.key",
        )
    assert parametros["ruta_base_datos"].read_bytes() == antes
