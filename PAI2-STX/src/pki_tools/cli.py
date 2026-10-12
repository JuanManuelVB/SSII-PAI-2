"""Crea la CA y certificados de servidor para el laboratorio PAI-2.

La API RF1 y el módulo RF5 consumen pki/ca/ca.crt y pki/ca/ca.key.
ATENCIÓN: la CA privada sin contraseña es exclusivamente para laboratorio local:
RF1 la carga con password=None. No debe desplegarse así en producción.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAIZ = Path(__file__).resolve().parents[2]


class ErrorPKI(ValueError):
    pass


def _guardar_par_sin_sobrescribir(clave: Path, cert: Path, pem_clave: bytes, pem_cert: bytes) -> None:
    """Escritura exclusiva: no sobrescribir jamás una CA o un certificado previo."""
    if clave.exists() or cert.exists():
        raise ErrorPKI(f"Ya existe una clave o certificado ({clave}, {cert}); no se reemplaza")
    clave.parent.mkdir(parents=True, exist_ok=True)
    cert.parent.mkdir(parents=True, exist_ok=True)
    creados: list[Path] = []
    try:
        for archivo, datos, modo in ((clave, pem_clave, 0o600), (cert, pem_cert, 0o644)):
            fd = os.open(str(archivo), os.O_WRONLY | os.O_CREAT | os.O_EXCL, modo)
            creados.append(archivo)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(datos)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != 'nt':
                archivo.chmod(modo)
    except Exception:
        for archivo in creados:
            archivo.unlink(missing_ok=True)
        raise


def _clave_y_certificado(ca_crt: Path, ca_key: Path):
    if not (ca_crt.is_file() and ca_key.is_file()):
        raise ErrorPKI('No existe la CA completa; ejecuta primero iniciar-ca')
    try:
        cert = x509.load_pem_x509_certificate(ca_crt.read_bytes())
        key = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    except (ValueError, TypeError, OSError) as exc:
        raise ErrorPKI('La clave o el certificado de CA no se pueden leer') from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ErrorPKI('Esta herramienta requiere una clave RSA para la CA')
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise ErrorPKI('El certificado CA no coincide con su clave privada')
    _validar_ca(cert)
    return cert, key


def _validar_ca(cert: x509.Certificate):
    ahora = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= ahora < cert.not_valid_after_utc):
        raise ErrorPKI('CA fuera del periodo de validez')
    try:
        restricciones = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        uso = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ErrorPKI('Faltan las extensiones de CA') from exc
    if not (restricciones.ca and uso.key_cert_sign):
        raise ErrorPKI('El certificado no está autorizado para firmar certificados')


def iniciar_ca(raiz: Path = RAIZ) -> tuple[Path, Path]:
    """Genera una única CA RSA de laboratorio. No la rota ni la reescribe."""
    keypath = raiz / 'pki' / 'ca' / 'ca.key'
    crtpath = raiz / 'pki' / 'ca' / 'ca.crt'
    if keypath.exists() or crtpath.exists():
        raise ErrorPKI('Ya hay ficheros de CA. No regenerarlos: invalidaría los certificados anteriores')
    clave = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    nombre = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'U-Secure PAI-2 (laboratorio)'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'U-Secure PAI-2 CA LOCAL'),
    ])
    ahora = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(nombre).issuer_name(nombre)
            .public_key(clave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora - timedelta(minutes=5))
            .not_valid_after(ahora + timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave.public_key()), critical=False)
            .sign(clave, hashes.SHA256()))
    _guardar_par_sin_sobrescribir(keypath, crtpath,
        clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()),
        cert.public_bytes(serialization.Encoding.PEM))
    return crtpath, keypath


def emitir_servidor(raiz: Path = RAIZ, dns: tuple[str, ...] = (),
                    ip: tuple[str, ...] = ()) -> tuple[Path, Path]:
    cert_ca, key_ca = _clave_y_certificado(raiz / 'pki' / 'ca' / 'ca.crt', raiz / 'pki' / 'ca' / 'ca.key')
    keypath = raiz / 'pki' / 'server' / 'server.key'
    crtpath = raiz / 'pki' / 'server' / 'server.crt'
    if keypath.exists() or crtpath.exists():
        raise ErrorPKI('El certificado del servidor ya existe. No se sobreescribe')
    nombres = ['localhost', *dns]
    direcciones = ['127.0.0.1', *ip]
    try:
        san = [x509.DNSName(nombre) for nombre in dict.fromkeys(nombres)] + [
            x509.IPAddress(ipaddress.ip_address(addr)) for addr in dict.fromkeys(direcciones)]
    except ValueError as exc:
        raise ErrorPKI(f'Nombre o dirección IP no válida: {exc}') from exc
    clave = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ahora = datetime.now(timezone.utc)
    caduca = min(ahora + timedelta(days=365), cert_ca.not_valid_after_utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(cert_ca.subject).public_key(clave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora - timedelta(minutes=5)).not_valid_after(caduca)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key_ca.public_key()), critical=False)
            .sign(key_ca, hashes.SHA256()))
    _guardar_par_sin_sobrescribir(keypath, crtpath,
        clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()),
        cert.public_bytes(serialization.Encoding.PEM))
    return crtpath, keypath


def verificar(raiz: Path = RAIZ) -> dict[str, str]:
    cert_ca, key_ca = _clave_y_certificado(raiz / 'pki' / 'ca' / 'ca.crt', raiz / 'pki' / 'ca' / 'ca.key')
    cert_ca.public_key().verify(cert_ca.signature, cert_ca.tbs_certificate_bytes,
                                padding.PKCS1v15(), cert_ca.signature_hash_algorithm)
    salida = {'ca': 'válida', 'ca_caduca': cert_ca.not_valid_after_utc.date().isoformat()}
    servidor_cert = raiz / 'pki' / 'server' / 'server.crt'
    servidor_key = raiz / 'pki' / 'server' / 'server.key'
    if servidor_cert.exists() or servidor_key.exists():
        if not (servidor_cert.is_file() and servidor_key.is_file()):
            raise ErrorPKI('Falta server.crt o server.key')
        cert = x509.load_pem_x509_certificate(servidor_cert.read_bytes())
        key = serialization.load_pem_private_key(servidor_key.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or cert.public_key().public_numbers() != key.public_key().public_numbers():
            raise ErrorPKI('La clave privada del servidor no coincide con el certificado')
        if cert.issuer != cert_ca.subject:
            raise ErrorPKI('El certificado del servidor no fue emitido por esta CA')
        cert_ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                    padding.PKCS1v15(), cert.signature_hash_algorithm)
        now = datetime.now(timezone.utc)
        if not (cert.not_valid_before_utc <= now < cert.not_valid_after_utc):
            raise ErrorPKI('Certificado de servidor caducado o todavía no válido')
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if 'localhost' not in san.get_values_for_type(x509.DNSName):
            raise ErrorPKI('Certificado del servidor sin SAN localhost')
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            raise ErrorPKI('Certificado del servidor sin serverAuth')
        salida['servidor'] = 'válido'
        salida['servidor_caduca'] = cert.not_valid_after_utc.date().isoformat()
    else:
        salida['servidor'] = 'no emitido'
    return salida


def main() -> int:
    parser = argparse.ArgumentParser(description='PKI de laboratorio compatible con RF1 y RF5 (PAI-2)')
    cmds = parser.add_subparsers(dest='accion', required=True)
    cmds.add_parser('iniciar-ca', help='crear la CA local una sola vez')
    s = cmds.add_parser('emitir-servidor', help='emitir certificado TLS de servidor con SAN')
    s.add_argument('--dns', action='append', default=[], help='DNS adicional; repetible')
    s.add_argument('--ip', action='append', default=[], help='IP adicional; repetible')
    cmds.add_parser('verificar', help='comprobar CA y certificado de servidor')
    args = parser.parse_args()
    try:
        if args.accion == 'iniciar-ca':
            crt, key = iniciar_ca()
            print(f'CA creada: {crt.relative_to(RAIZ)}; clave PRIVADA: {key.relative_to(RAIZ)}')
        elif args.accion == 'emitir-servidor':
            crt, key = emitir_servidor(dns=tuple(args.dns), ip=tuple(args.ip))
            print(f'Servidor emitido: {crt.relative_to(RAIZ)}; clave PRIVADA: {key.relative_to(RAIZ)}')
        else:
            for k, v in verificar().items():
                print(f'{k}: {v}')
        return 0
    except (ErrorPKI, OSError, ValueError) as exc:
        print(f'Error PKI: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
