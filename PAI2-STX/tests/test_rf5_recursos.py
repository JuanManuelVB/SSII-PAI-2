"""Recursos adicionales para probar RF5 de forma aislada y reproducible."""

import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from src.common.base_datos import conectar_base_datos
from src.rf5 import gestion


def _rutas(tmp_path):
    """Devuelve rutas temporales para que la prueba nunca use datos reales."""
    return {
        "ruta_base_datos": tmp_path / "rf5.sqlite3",
        "ruta_credenciales": tmp_path / "credenciales.csv",
    }


def _crear_ca(tmp_path):
    """Crea una CA mínima y válida para probar la emisión de certificados."""
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "CA de pruebas")])
    ahora = datetime.now(timezone.utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(minutes=1))
        .not_valid_after(ahora + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(clave, hashes.SHA256())
    )
    ruta_cert = tmp_path / "ca.crt"
    ruta_key = tmp_path / "ca.key"
    ruta_cert.write_bytes(certificado.public_bytes(serialization.Encoding.PEM))
    ruta_key.write_bytes(
        clave.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ruta_cert, ruta_key


def test_csv_invalido_se_rechaza_sin_sobrescribirlo(tmp_path):
    """Un CSV manipulado no debe ser aceptado como fuente de credenciales."""
    rutas = _rutas(tmp_path)
    rutas["ruta_credenciales"].write_text("username,password\ncuenta,secreta\n")

    with pytest.raises(gestion.ErrorRF5, match="CSV de credenciales previo inválido"):
        gestion.precargar_usuarios(3, **rutas)

    assert rutas["ruta_credenciales"].read_text() == "username,password\ncuenta,secreta\n"


def test_cli_precargar_y_resumen_son_ejecutables(tmp_path):
    """Comprueba la interfaz real de terminal sin depender de una shell."""
    proceso = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.rf5.cli",
            "precargar",
            "--total",
            "3",
            "--db",
            str(tmp_path / "rf5.sqlite3"),
            "--credenciales",
            str(tmp_path / "credenciales.csv"),
        ],
        cwd=gestion.RAIZ,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proceso.returncode == 0, proceso.stderr
    assert '"nuevos": 3' in proceso.stdout


def test_emision_registra_propiedades_de_certificado_cliente(tmp_path):
    """Comprueba EKU clientAuth, huella pública y relación usuario-dispositivo."""
    rutas = _rutas(tmp_path)
    gestion.precargar_usuarios(3, **rutas)
    ruta_ca, ruta_key = _crear_ca(tmp_path)
    destino = tmp_path / "clientes"

    gestion.emitir_certificados(
        ruta_base_datos=rutas["ruta_base_datos"],
        directorio_destino=destino,
        ruta_ca_cert=ruta_ca,
        ruta_ca_key=ruta_key,
        limite=1,
    )

    ruta_certificado = next(destino.glob("*.crt"))
    certificado = x509.load_pem_x509_certificate(ruta_certificado.read_bytes())
    eku = certificado.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    with conectar_base_datos(rutas["ruta_base_datos"]) as conexion:
        emparejamiento = conexion.execute(
            "SELECT username, device_id, certificate_path FROM device_pairings"
        ).fetchone()
    assert certificado.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )[0].value == emparejamiento["device_id"]
    assert tuple(emparejamiento) == (
        "rf5_inv_001",
        "rf5-inv-001-dev01",
        "pki/clients/rf5/rf5_inv_001.crt",
    )
