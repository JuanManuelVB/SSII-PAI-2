"""Auditoría pública de RF1, RF5 y RS1; no abre claves ni imprime secretos.

Ejemplo: python -m tools.auditar_rf1_rf5_pki --total 300 --json evidencias/logs/auditoria_pki.json
"""
from __future__ import annotations
import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO, conectar_base_datos
from src.rf5.gestion import RUTA_CA_CERT, DIRECTORIO_PRIVADO


def verificar_firma(cert: x509.Certificate, ca: x509.Certificate) -> None:
    clave = ca.public_key()
    if isinstance(clave, rsa.RSAPublicKey):
        clave.verify(cert.signature, cert.tbs_certificate_bytes,
                     padding.PKCS1v15(), cert.signature_hash_algorithm)
    elif isinstance(clave, ec.EllipticCurvePublicKey):
        clave.verify(cert.signature, cert.tbs_certificate_bytes,
                     ec.ECDSA(cert.signature_hash_algorithm))
    else:
        raise ValueError('tipo de CA no admitido')


def comprobar(ruta_db: Path, ruta_ca: Path, directorio: Path, total: int) -> dict:
    problemas: list[str] = []
    if not ruta_db.is_file() or not ruta_ca.is_file():
        return {'aprobado': False, 'problemas': ['Falta SQLite o certificado público CA']}
    ca = x509.load_pem_x509_certificate(ruta_ca.read_bytes())
    ahora = datetime.now(timezone.utc)
    try:
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            problemas.append('El certificado CA no tiene CA:TRUE')
        if not ca.not_valid_before_utc <= ahora <= ca.not_valid_after_utc:
            problemas.append('CA fuera de vigencia')
    except x509.ExtensionNotFound:
        problemas.append('CA carece de BasicConstraints')
    with conectar_base_datos(ruta_db) as db:
        usuarios = db.execute("SELECT username,role,status FROM users WHERE origin='RF5'").fetchall()
        parejas = db.execute("""SELECT p.username,p.device_id,p.status,p.certificate_serial,
                               p.public_key_fingerprint FROM device_pairings p
                               JOIN users u ON u.username=p.username WHERE u.origin='RF5'""").fetchall()
    roles = dict(Counter(u['role'] for u in usuarios))
    if set(roles) != {'PDI', 'PAS', 'INVESTIGADOR'}:
        problemas.append('Falta alguno de los tres roles RF5')
    if total == 300 and any(roles.get(r) != 100 for r in ('PDI', 'PAS', 'INVESTIGADOR')):
        problemas.append('RF5: se esperaban 100 PDI, 100 PAS y 100 Investigadores')
    ruta_revocados = ruta_ca.parent / 'revoked.json'
    seriales_revocados = set()
    if ruta_revocados.is_file():
        try:
            seriales_revocados = {str(x['serial']) for x in json.loads(ruta_revocados.read_text(encoding='utf-8'))}
        except (ValueError, TypeError, KeyError):
            problemas.append('El registro de certificados revocados es inválido')
    if len(usuarios) != total:
        problemas.append(f'Usuarios RF5: {len(usuarios)}/{total}')
    if any(u['status'] != 'active' for u in usuarios):
        problemas.append('Hay cuentas RF5 no activas (revisar si es intencional)')
    emitidos = 0
    errores_cert: list[str] = []
    for registro in parejas:
        nombre = registro['username']
        if registro['status'] != 'active':
            continue
        ruta = directorio / f'{nombre}.crt'
        if not ruta.is_file():
            errores_cert.append(f'{nombre}: falta .crt')
            continue
        try:
            cert = x509.load_pem_x509_certificate(ruta.read_bytes())
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
            huella = hashlib.sha256(cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            if cert.issuer != ca.subject:
                raise ValueError('emisor CA incorrecto')
            if str(cert.serial_number) in seriales_revocados:
                raise ValueError('certificado revocado todavía asociado como activo')
            verificar_firma(cert, ca)
            if not cert.not_valid_before_utc <= ahora <= cert.not_valid_after_utc:
                raise ValueError('certificado caducado/no vigente')
            if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError('certificado cliente con privilegios CA')
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
                raise ValueError('falta clientAuth')
            if (cn != registro['device_id'] or ou != nombre or
                str(cert.serial_number) != registro['certificate_serial'] or
                huella != registro['public_key_fingerprint']):
                raise ValueError('certificado no coincide con emparejamiento inmutable')
            emitidos += 1
        except (ValueError, IndexError, InvalidSignature, x509.ExtensionNotFound) as exc:
            errores_cert.append(f'{nombre}: {exc}')
    if errores_cert:
        problemas.append(f'{len(errores_cert)} certificados emitidos no verificables')
    # El enunciado exige certificados para las cuentas precargadas.
    if emitidos != total:
        problemas.append(f'Certificados activos verificables: {emitidos}/{total}')
    return {'aprobado': not problemas, 'total_usuarios_rf5':len(usuarios),
            'por_rol':roles, 'certificados_verificados':emitidos,
            'emparejamientos':len(parejas), 'problemas':problemas,
            'detalle_certificados':errores_cert[:20]}


def main() -> int:
    p = argparse.ArgumentParser(description='Auditar RF1, RF5 y RS1 sin leer secretos')
    p.add_argument('--db', type=Path, default=RUTA_BASE_DATOS_POR_DEFECTO)
    p.add_argument('--ca', type=Path, default=RUTA_CA_CERT)
    p.add_argument('--certificados', type=Path, default=DIRECTORIO_PRIVADO)
    p.add_argument('--total', type=int, default=300)
    p.add_argument('--json', type=Path)
    args = p.parse_args()
    resultado = comprobar(args.db, args.ca, args.certificados, args.total)
    salida = json.dumps(resultado, indent=2, ensure_ascii=False)
    print(salida)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(salida + '\n', encoding='utf-8')
    return 0 if resultado['aprobado'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
