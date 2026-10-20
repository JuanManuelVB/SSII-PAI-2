"""Verificar un certificado RF1 emitido DE VERDAD y su vinculo a SQLite.

Ejecutar desde PAI2-STX: py -m tools.verificar_certificado_real --dispositivo rf1_demo_01
No modifica certificados, claves ni base de datos. No imprime secretos.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAIZ = Path(__file__).resolve().parents[1]


def comprobar(dispositivo: str) -> bool:
    if not dispositivo or not dispositivo.replace('_','').replace('-','').replace('.','').isalnum() or '/' in dispositivo or '\\' in dispositivo:
        raise ValueError('Identificador de dispositivo no valido')
    cert_file = RAIZ / 'pki' / 'clients' / (dispositivo + '.crt')
    key_file = RAIZ / 'pki' / 'clients' / (dispositivo + '.key')
    ca_file = RAIZ / 'pki' / 'ca' / 'ca.crt'
    db_file = RAIZ / 'data' / 'rf1.sqlite3'
    for path in (cert_file, key_file, ca_file, db_file):
        if not path.is_file():
            raise FileNotFoundError(f'Falta el archivo necesario: {path.relative_to(RAIZ)}')

    cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
    ca = x509.load_pem_x509_certificate(ca_file.read_bytes())
    key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    now = datetime.now(timezone.utc)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
    checks = {
        'Emisor es la CA corporativa': cert.issuer == ca.subject,
        'CA autorizada para firmar': ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
        'CA vigente': ca.not_valid_before_utc <= now <= ca.not_valid_after_utc,
        'Certificado vigente': cert.not_valid_before_utc <= now <= cert.not_valid_after_utc,
        'CN corresponde al dispositivo': cn == dispositivo,
        'Certificado no es autoridad CA': not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
        'Uso exclusivo habilitado: clientAuth': ExtendedKeyUsageOID.CLIENT_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
    }
    pub = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_key = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    checks['Clave privada corresponde al certificado'] = (pub == pub_key)
    ca_pub = ca.public_key()
    try:
        if isinstance(ca_pub, rsa.RSAPublicKey):
            ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                          padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(ca_pub, ec.EllipticCurvePublicKey):
            ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                          ec.ECDSA(cert.signature_hash_algorithm))
        else:
            raise ValueError('Algoritmo de firma de CA no reconocido')
        checks['Firma criptografica verificada'] = True
    except Exception:
        checks['Firma criptografica verificada'] = False
    with sqlite3.connect(f'file:{db_file.as_posix()}?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        pairing = db.execute('SELECT username, device_id, public_key_fingerprint, certificate_serial, status '
                             'FROM device_pairings WHERE device_id = ?', (dispositivo,)).fetchone()
    fingerprint = hashlib.sha256(pub).hexdigest()
    checks['Dispositivo registrado en SQLite'] = pairing is not None
    if pairing:
        checks['Certificado vinculado al usuario'] = pairing['username'] == ou
        checks['Numero de serie coincide con SQLite'] = pairing['certificate_serial'] == str(cert.serial_number)
        checks['Huella publica coincide con SQLite'] = pairing['public_key_fingerprint'] == fingerprint
        checks['Emparejamiento activo'] = pairing['status'] == 'active'
    revocados_path = RAIZ / 'pki' / 'ca' / 'revoked.json'
    if revocados_path.exists():
        revoked = json.loads(revocados_path.read_text(encoding='utf-8'))
        checks['No figura en revocados'] = str(cert.serial_number) not in {str(r['serial']) for r in revoked}

    print(f'\nCERTIFICADO RF1: {dispositivo}')
    print(f'Usuario: {ou}')
    print(f'Emisor: {cert.issuer.rfc4514_string()}')
    print(f'Serie: {cert.serial_number}')
    print(f'Validez UTC: {cert.not_valid_before_utc.isoformat()} -> {cert.not_valid_after_utc.isoformat()}')
    print(f'Certificado: {cert_file.relative_to(RAIZ)}')
    print(f'Clave privada: {key_file.relative_to(RAIZ)} (CONTENIDO OCULTO)')
    for titulo, success in checks.items():
        print(f"  {'[OK]' if success else '[ERROR]'} {titulo}")
    passed = all(checks.values())
    print('\nRESULTADO: ' + ('CERTIFICADO VALIDO Y EMPAREJADO' if passed else 'VERIFICACION FALLIDA'))
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description='Verificar RF1 real: firma de CA, clave, validez y BD')
    parser.add_argument('--dispositivo', required=True)
    arg = parser.parse_args()
    try:
        return 0 if comprobar(arg.dispositivo) else 1
    except (ValueError, OSError, sqlite3.Error, IndexError, KeyError, x509.ExtensionNotFound) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
