"""Herramientas de laboratorio para gestionar la PKI de PAI2-STX.

La PKI tiene tres niveles de material:

* ``ca/``: clave privada y certificado de la autoridad corporativa.
* ``server/``: clave y certificado que presenta el gateway.
* ``clients/``: certificados de los dispositivos BYOD.

La clave privada de la CA es el secreto más importante del laboratorio.
Este script no la imprime y nunca la sube al repositorio.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAIZ = Path(__file__).resolve().parents[2]
DIRECTORIO_CA = RAIZ / "pki" / "ca"
DIRECTORIO_SERVIDOR = RAIZ / "pki" / "server"
DIRECTORIO_CLIENTES = RAIZ / "pki" / "clients"
RUTA_REVOCADOS = DIRECTORIO_CA / "revoked.json"
RUTA_CRL = DIRECTORIO_CA / "ca.crl.pem"


class ErrorPKI(ValueError):
    """Error controlado para entradas inválidas o material PKI inconsistente."""


def _rutas_raiz(raiz: Path) -> dict[str, Path]:
    """Calcula todas las rutas PKI a partir de una raíz configurable."""
    pki = raiz / "pki"
    return {
        "ca": pki / "ca",
        "server": pki / "server",
        "clients": pki / "clients",
        "revocados": pki / "ca" / "revoked.json",
        "crl": pki / "ca" / "ca.crl.pem",
    }


def _ahora() -> datetime:
    """Devuelve una fecha UTC consciente de zona horaria."""
    return datetime.now(timezone.utc)


def _escribir_atomico(ruta: Path, contenido: bytes, privado: bool = False) -> None:
    """Escribe un archivo temporal y lo sustituye al terminar correctamente."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporal = tempfile.mkstemp(prefix=".pki-", dir=ruta.parent)
    try:
        with os.fdopen(descriptor, "wb") as archivo:
            archivo.write(contenido)
            archivo.flush()
            os.fsync(archivo.fileno())
        os.chmod(temporal, 0o600 if privado else 0o644)
        os.replace(temporal, ruta)
    finally:
        if os.path.exists(temporal):
            os.unlink(temporal)


def _guardar_clave(ruta: Path, clave) -> None:
    """Guarda una clave privada PEM sin contraseña para el laboratorio local."""
    _escribir_atomico(
        ruta,
        clave.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        privado=True,
    )


def _guardar_certificado(ruta: Path, certificado: x509.Certificate) -> None:
    """Guarda un certificado PEM público."""
    _escribir_atomico(ruta, certificado.public_bytes(serialization.Encoding.PEM))


def _cargar_ca(raiz: Path):
    """Carga la CA y su clave, comprobando que ambas partes coincidan."""
    rutas = _rutas_raiz(raiz)
    try:
        certificado = x509.load_pem_x509_certificate(
            (rutas["ca"] / "ca.crt").read_bytes()
        )
        clave = serialization.load_pem_private_key(
            (rutas["ca"] / "ca.key").read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError) as exc:
        raise ErrorPKI("No se puede cargar pki/ca/ca.crt y pki/ca/ca.key") from exc

    clave_publica = clave.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_publico = certificado.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if clave_publica != cert_publico:
        raise ErrorPKI("La clave privada de la CA no corresponde a ca.crt")
    if not certificado.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value.ca:
        raise ErrorPKI("ca.crt no está marcado como autoridad certificadora")
    return certificado, clave


def crear_ca(raiz: Path, nombre: str = "PAI2-STX Corporate CA", dias: int = 3650) -> None:
    """Crea la CA raíz una sola vez; nunca sobrescribe una CA existente."""
    if dias < 1:
        raise ErrorPKI("La duración debe ser positiva")
    rutas = _rutas_raiz(raiz)
    cert_path, key_path = rutas["ca"] / "ca.crt", rutas["ca"] / "ca.key"
    if cert_path.exists() or key_path.exists():
        raise ErrorPKI("La CA ya existe o está incompleta; no se sobrescribe")

    clave = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
    inicio = _ahora() - timedelta(minutes=5)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(sujeto)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(inicio)
        .not_valid_after(inicio + timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(clave.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(clave, hashes.SHA256())
    )
    _guardar_clave(key_path, clave)
    _guardar_certificado(cert_path, certificado)
    _escribir_atomico(rutas["revocados"], b"[]\n")


def _crear_certificado(
    raiz: Path,
    nombre_comun: str,
    clave: rsa.RSAPrivateKey,
    uso: ExtendedKeyUsageOID,
    dias: int,
    nombres_dns: list[str],
    ips: list[str],
) -> x509.Certificate:
    """Firma un certificado de servidor o cliente con la CA corporativa."""
    ca, clave_ca = _cargar_ca(raiz)
    if dias < 1:
        raise ErrorPKI("La duración debe ser positiva")
    inicio = _ahora() - timedelta(minutes=5)
    fin = min(inicio + timedelta(days=dias), ca.not_valid_after_utc)
    nombres = [x509.DNSName(nombre) for nombre in nombres_dns]
    nombres.extend(x509.IPAddress(ip_address(ip)) for ip in ips)
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre_comun)])
    return (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(ca.subject)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(inicio)
        .not_valid_after(fin)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([uso]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(nombres),
            critical=(uso == ExtendedKeyUsageOID.SERVER_AUTH),
        )
        .sign(clave_ca, hashes.SHA256())
    )


def emitir_servidor(
    raiz: Path,
    nombre: str = "localhost",
    dias: int = 825,
    nombres_dns: list[str] | None = None,
    ips: list[str] | None = None,
) -> None:
    """Emite el certificado que presentará el gateway VPN."""
    rutas = _rutas_raiz(raiz)
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificado = _crear_certificado(
        raiz,
        nombre,
        clave,
        ExtendedKeyUsageOID.SERVER_AUTH,
        dias,
        nombres_dns or [nombre],
        ips or ["127.0.0.1"],
    )
    _guardar_clave(rutas["server"] / "server.key", clave)
    _guardar_certificado(rutas["server"] / "server.crt", certificado)


def emitir_cliente(raiz: Path, nombre: str, dias: int = 365) -> None:
    """Emite un certificado cliente con uso exclusivo de autenticación cliente."""
    if not nombre or Path(nombre).name != nombre:
        raise ErrorPKI("El nombre del cliente debe ser un identificador simple")
    rutas = _rutas_raiz(raiz)
    directorio = rutas["clients"] / nombre
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificado = _crear_certificado(
        raiz, nombre, clave, ExtendedKeyUsageOID.CLIENT_AUTH, dias, [], []
    )
    _guardar_clave(directorio / f"{nombre}.key", clave)
    _guardar_certificado(directorio / f"{nombre}.crt", certificado)


def _leer_revocados(raiz: Path) -> list[dict[str, str]]:
    """Lee la lista sencilla de números revocados que alimenta la CRL."""
    rutas = _rutas_raiz(raiz)
    if not rutas["revocados"].exists():
        return []
    try:
        datos = json.loads(rutas["revocados"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ErrorPKI("revoked.json no es válido") from exc
    if not isinstance(datos, list):
        raise ErrorPKI("revoked.json debe contener una lista")
    return datos


def revocar(raiz: Path, certificado_path: Path, razon: str = "cessationOfOperation") -> None:
    """Añade un certificado a la lista de revocados y regenera la CRL."""
    certificado = x509.load_pem_x509_certificate(certificado_path.read_bytes())
    ca, _ = _cargar_ca(raiz)
    if certificado.issuer != ca.subject:
        raise ErrorPKI("El certificado no fue emitido por esta CA")
    revocados = _leer_revocados(raiz)
    serial = str(certificado.serial_number)
    if not any(item["serial"] == serial for item in revocados):
        revocados.append(
            {
                "serial": serial,
                "revoked_at": _ahora().isoformat(),
                "reason": razon,
            }
        )
    rutas = _rutas_raiz(raiz)
    _escribir_atomico(
        rutas["revocados"],
        (json.dumps(revocados, indent=2) + "\n").encode("utf-8"),
    )
    generar_crl(raiz)


def generar_crl(raiz: Path) -> None:
    """Genera una CRL PEM firmada por la CA a partir de revoked.json."""
    ca, clave_ca = _cargar_ca(raiz)
    constructor = x509.CertificateRevocationListBuilder()
    constructor = constructor.issuer_name(ca.subject).last_update(_ahora())
    constructor = constructor.next_update(_ahora() + timedelta(days=7))
    for item in _leer_revocados(raiz):
        constructor = constructor.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(int(item["serial"]))
            .revocation_date(datetime.fromisoformat(item["revoked_at"]))
            .build()
        )
    _escribir_atomico(
        _rutas_raiz(raiz)["crl"],
        constructor.sign(private_key=clave_ca, algorithm=hashes.SHA256()).public_bytes(
            serialization.Encoding.PEM
        ),
    )


def verificar(raiz: Path, certificado_path: Path) -> bool:
    """Comprueba emisor, vigencia y ausencia en la CRL local."""
    ca, _ = _cargar_ca(raiz)
    certificado = x509.load_pem_x509_certificate(certificado_path.read_bytes())
    ahora = _ahora()
    if certificado.issuer != ca.subject:
        return False
    if not (certificado.not_valid_before_utc <= ahora <= certificado.not_valid_after_utc):
        return False
    return not any(
        item["serial"] == str(certificado.serial_number)
        for item in _leer_revocados(raiz)
    )


def main() -> int:
    """Expone las operaciones principales como comandos de terminal."""
    parser = argparse.ArgumentParser(description="Gestión PKI de PAI2-STX")
    parser.add_argument("--root", type=Path, default=RAIZ, help="Raíz del proyecto")
    sub = parser.add_subparsers(dest="comando", required=True)

    ca = sub.add_parser("crear-ca")
    ca.add_argument("--nombre", default="PAI2-STX Corporate CA")
    ca.add_argument("--dias", type=int, default=3650)
    servidor = sub.add_parser("emitir-servidor")
    servidor.add_argument("--nombre", default="localhost")
    servidor.add_argument("--dias", type=int, default=825)
    cliente = sub.add_parser("emitir-cliente")
    cliente.add_argument("nombre")
    cliente.add_argument("--dias", type=int, default=365)
    revocacion = sub.add_parser("revocar")
    revocacion.add_argument("certificado", type=Path)
    revocacion.add_argument("--razon", default="cessationOfOperation")
    crl = sub.add_parser("generar-crl")
    validar = sub.add_parser("verificar")
    validar.add_argument("certificado", type=Path)
    args = parser.parse_args()

    try:
        if args.comando == "crear-ca":
            crear_ca(args.root, args.nombre, args.dias)
        elif args.comando == "emitir-servidor":
            emitir_servidor(args.root, args.nombre, args.dias)
        elif args.comando == "emitir-cliente":
            emitir_cliente(args.root, args.nombre, args.dias)
        elif args.comando == "revocar":
            revocar(args.root, args.certificado, args.razon)
        elif args.comando == "generar-crl":
            generar_crl(args.root)
        else:
            print("VÁLIDO" if verificar(args.root, args.certificado) else "REVOCADO/INVÁLIDO")
        return 0
    except (ErrorPKI, OSError, ValueError) as exc:
        parser.exit(1, f"Error PKI: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
