"""Pruebas aisladas del ciclo de vida PKI."""

import subprocess
import sys

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from pki.scripts import pki


def test_pki_emite_servidor_cliente_y_revoca(tmp_path):
    print("[PKI] Creando CA temporal y emitiendo certificados de servidor y cliente")
    pki.crear_ca(tmp_path, dias=30)
    pki.emitir_servidor(tmp_path)
    pki.emitir_cliente(tmp_path, "pdi001")

    servidor = tmp_path / "pki" / "server" / "server.crt"
    cliente = tmp_path / "pki" / "clients" / "pdi001" / "pdi001.crt"
    cert_servidor = x509.load_pem_x509_certificate(servidor.read_bytes())
    cert_cliente = x509.load_pem_x509_certificate(cliente.read_bytes())
    assert ExtendedKeyUsageOID.SERVER_AUTH in cert_servidor.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in cert_cliente.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value
    assert pki.verificar(tmp_path, cliente)
    print("[PKI] Certificados emitidos: serverAuth y clientAuth verificados")

    print("[PKI] Revocando el certificado cliente y generando la CRL")
    pki.revocar(tmp_path, cliente)
    assert not pki.verificar(tmp_path, cliente)
    crl = x509.load_pem_x509_crl(
        (tmp_path / "pki" / "ca" / "ca.crl.pem").read_bytes()
    )
    assert any(item.serial_number == cert_cliente.serial_number for item in crl)
    print("[PKI] Certificado revocado: verificación negativa y CRL confirmada")


def test_cli_pki_funciona(tmp_path):
    print("[PKI] Ejecutando el comando CLI crear-ca en una raíz temporal")
    comando = [
        sys.executable,
        "-m",
        "pki.scripts.pki",
        "--root",
        str(tmp_path),
        "crear-ca",
    ]
    resultado = subprocess.run(comando, capture_output=True, text=True, check=False)
    assert resultado.returncode == 0, resultado.stderr
    print("[PKI] CLI finalizó correctamente")


def test_certificados_nuevos_tienen_aki_ski_y_validacion_estricta(tmp_path):
    pki.crear_ca(tmp_path)
    pki.emitir_servidor(tmp_path, nombre="localhost")
    root = tmp_path / "pki"
    for target in ("ca/ca.crt", "server/server.crt"):
        cert = x509.load_pem_x509_certificate((root / target).read_bytes())
        cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    salida = subprocess.run([
        "openssl", "verify", "-x509_strict", "-purpose", "sslserver",
        "-verify_hostname", "localhost", "-CAfile", str(root / "ca/ca.crt"),
        str(root / "server/server.crt")
    ], text=True, capture_output=True)
    assert salida.returncode == 0, salida.stderr
