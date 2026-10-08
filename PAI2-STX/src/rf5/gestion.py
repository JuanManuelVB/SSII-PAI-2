"""RF5 - usuarios corporativos preexistentes sin cambiar RF1/RF2/RF4.

Contrato con src/server/app.py: el fichero usuarios.json es una lista de
objetos con username, password_hash (scrypt$salt$hash) y status='active'.
Los roles son metadatos RF5. Los certificados X.509 se emiten después, cuando
el compañero haya configurado pki/ca/ca.crt y pki/ca/ca.key.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import secrets
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAIZ = Path(__file__).resolve().parents[2]
RUTA_USUARIOS = RAIZ / "data" / "usuarios_precargados" / "usuarios.json"
DIRECTORIO_PRIVADO = RAIZ / "pki" / "clients" / "rf5"
RUTA_CREDENCIALES = DIRECTORIO_PRIVADO / "credenciales.csv"
RUTA_CA_CERT = RAIZ / "pki" / "ca" / "ca.crt"
RUTA_CA_KEY = RAIZ / "pki" / "ca" / "ca.key"

# No existe matriz de permisos en el enunciado; aquí solo se identifican perfiles.
PERFILES = {"PDI": "pdi", "PAS": "pas", "Investigador": "inv"}
CAMPOS_CREDENCIALES = ("username", "password", "role", "device_id")


class ErrorRF5(ValueError):
    """Error explícito de datos/configuración: no se reescribe el fichero."""


def cargar_usuarios(ruta: Path = RUTA_USUARIOS) -> list[dict]:
    """Carga la lista original sin renombrar ni cambiar registros ajenos."""
    if not ruta.exists():
        return []
    try:
        contenido = json.loads(ruta.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ErrorRF5(f"JSON inválido en {ruta}; no se sobrescribirá") from exc
    if not isinstance(contenido, list):
        raise ErrorRF5("usuarios.json debe ser una lista JSON")
    ids = set()
    for usuario in contenido:
        if not isinstance(usuario, dict) or not isinstance(usuario.get("username"), str):
            raise ErrorRF5("Cada registro debe ser un objeto con username de texto")
        if usuario["username"] in ids:
            raise ErrorRF5(f"Username duplicado: {usuario['username']}")
        ids.add(usuario["username"])
    return contenido


def _escribir_atomico(ruta: Path, texto: str, *, privado: bool) -> None:
    """Nunca deja un fichero incompleto; credenciales legibles solo por dueño."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    fd, temporal = tempfile.mkstemp(prefix=".rf5-", dir=ruta.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(texto)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporal, 0o600 if privado else 0o644)
        os.replace(temporal, ruta)
    finally:
        if os.path.exists(temporal):
            os.unlink(temporal)


def _hash_password(password: str) -> str:
    # Misma codificación y parámetros que src/server/app.py (RF1).
    sal = secrets.token_bytes(16)
    resumen = hashlib.scrypt(password.encode("utf-8"), salt=sal, n=2**14, r=8, p=1)
    return f"scrypt${sal.hex()}${resumen.hex()}"


def reparto_roles(total: int) -> dict[str, int]:
    if not isinstance(total, int) or isinstance(total, bool) or total < 3 or total > 3000:
        raise ErrorRF5("El total debe estar entre 3 y 3000")
    base, resto = divmod(total, len(PERFILES))
    return {rol: base + (indice < resto) for indice, rol in enumerate(PERFILES)}


def _leer_credenciales(ruta: Path) -> list[dict[str, str]]:
    if not ruta.exists():
        return []
    with ruta.open("r", encoding="utf-8", newline="") as f:
        lector = csv.DictReader(f)
        if tuple(lector.fieldnames or []) != CAMPOS_CREDENCIALES:
            raise ErrorRF5("CSV de credenciales previo inválido; no será sobrescrito")
        registros = list(lector)
    nombres = [r["username"] for r in registros]
    if len(nombres) != len(set(nombres)):
        raise ErrorRF5("CSV de credenciales contiene usernames duplicados")
    return registros


def _csv_credenciales(credenciales: list[dict[str, str]]) -> str:
    import io

    salida = io.StringIO(newline="")
    escritor = csv.DictWriter(salida, fieldnames=CAMPOS_CREDENCIALES)
    escritor.writeheader()
    escritor.writerows(credenciales)
    return salida.getvalue()


def precargar_usuarios(
    total: int = 300,
    *,
    ruta_usuarios: Path = RUTA_USUARIOS,
    ruta_credenciales: Path = RUTA_CREDENCIALES,
) -> dict[str, object]:
    """Añade únicamente cuentas RF5 que falten; es idempotente.

    Los secretos se guardan SOLO en CSV privado local ignorado por Git; JSON
    contiene hashes compatibles con RF1. No modifica usuarios ya existentes.
    """
    reparto = reparto_roles(total)
    usuarios = cargar_usuarios(ruta_usuarios)
    por_nombre = {u["username"]: u for u in usuarios}
    credenciales = _leer_credenciales(ruta_credenciales)
    nombres_credenciales = {c["username"] for c in credenciales}
    nuevas_cuentas = []
    nuevas_credenciales = []
    for rol, prefijo in PERFILES.items():
        for numero in range(1, reparto[rol] + 1):
            username = f"rf5_{prefijo}_{numero:03d}"
            device_id = f"rf5-{prefijo}-{numero:03d}-dev01"
            previo = por_nombre.get(username)
            if previo is not None:
                if previo.get("role") != rol or previo.get("origin") != "RF5":
                    raise ErrorRF5(f"Colisión con usuario ajeno al RF5: {username}")
                continue
            if username in nombres_credenciales:
                raise ErrorRF5(f"Existen credenciales sin cuenta para {username}; revisar")
            password = secrets.token_urlsafe(24)
            nuevas_cuentas.append({
                "username": username,
                "password_hash": _hash_password(password),
                "status": "active",
                "role": rol,
                "origin": "RF5",
                "device_id": device_id,
                "certificate_status": "pending",
            })
            nuevas_credenciales.append({
                "username": username,
                "password": password,
                "role": rol,
                "device_id": device_id,
            })
    if nuevas_cuentas:
        # Primero queda a salvo el secreto. Si falla el guardado de usuarios,
        # puede recuperarse el CSV; jamás se sustituye un secreto existente.
        _escribir_atomico(ruta_credenciales, _csv_credenciales(credenciales + nuevas_credenciales), privado=True)
        _escribir_atomico(
            ruta_usuarios,
            json.dumps(usuarios + nuevas_cuentas, indent=2, ensure_ascii=False) + "\n",
            privado=True,
        )
    return {"nuevos": len(nuevas_cuentas), "total_rf5": sum(
        u.get("origin") == "RF5" for u in usuarios + nuevas_cuentas
    ), "reparto_solicitado": reparto, "ruta_usuarios": str(ruta_usuarios),
        "ruta_credenciales_privadas": str(ruta_credenciales)}



def consultar_perfil(username: str, ruta: Path = RUTA_USUARIOS) -> dict[str, str] | None:
    """Devuelve perfil y certificado asociado solo para usuarios RF5 activos.

    Esta consulta NO autentica al dispositivo; el gateway debe verificar mTLS.
    """
    for usuario in cargar_usuarios(ruta):
        if (usuario.get("username") == username and usuario.get("origin") == "RF5"
                and usuario.get("status") == "active"
                and usuario.get("role") in PERFILES):
            return {
                "username": usuario["username"],
                "role": usuario["role"],
                "device_id": usuario.get("device_id", ""),
                "certificate_serial": usuario.get("certificate_serial", ""),
                "certificate_status": usuario.get("certificate_status", "pending"),
            }
    return None


def resumen_usuarios(ruta: Path = RUTA_USUARIOS) -> dict[str, object]:
    """Resumen sin exponer contraseñas ni datos de terceros."""
    usuarios = [u for u in cargar_usuarios(ruta) if u.get("origin") == "RF5"]
    return {
        "total_rf5": len(usuarios),
        "por_rol": dict(Counter(u.get("role", "sin_rol") for u in usuarios)),
        "certificados_emitidos": sum(u.get("certificate_status") == "issued" for u in usuarios),
        "usuarios_activos": sum(u.get("status") == "active" for u in usuarios),
    }


def _cargar_ca(ruta_cert: Path, ruta_key: Path):
    if not ruta_cert.is_file() or not ruta_key.is_file():
        raise ErrorRF5(
            "Falta la CA del compañero: pki/ca/ca.crt y/o pki/ca/ca.key. "
            "Solicita esos archivos antes de emitir certificados; no se creará otra CA."
        )
    try:
        cert = x509.load_pem_x509_certificate(ruta_cert.read_bytes())
        clave = serialization.load_pem_private_key(ruta_key.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise ErrorRF5("La CA no tiene formato PEM válido o la clave está cifrada") from exc
    if not isinstance(clave, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ErrorRF5("La CA debe usar clave RSA o EC")
    pub_ca = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_key = clave.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not secrets.compare_digest(pub_ca, pub_key):
        raise ErrorRF5("La clave privada de CA no corresponde al certificado")
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ErrorRF5("La CA no declara BasicConstraints") from exc
    if not bc.ca:
        raise ErrorRF5("El certificado de firma no es de CA")
    ahora = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= ahora <= cert.not_valid_after_utc):
        raise ErrorRF5("El certificado de CA no está vigente")
    return cert, clave


def _certificado_valido(certificado: x509.Certificate, clave, ca_cert, username: str, device_id: str) -> bool:
    if certificado.issuer != ca_cert.subject:
        return False
    cn = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ou = certificado.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if len(cn) != 1 or cn[0].value != device_id or len(ou) != 1 or ou[0].value != username:
        return False
    ahora = datetime.now(timezone.utc)
    if not (certificado.not_valid_before_utc <= ahora <= certificado.not_valid_after_utc):
        return False
    pub_cert = certificado.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_key = clave.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not secrets.compare_digest(pub_cert, pub_key):
        return False
    try:
        ekus = certificado.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    if ExtendedKeyUsageOID.CLIENT_AUTH not in ekus:
        return False
    # Validar la firma de la CA, no solo comprobar el nombre del emisor.
    try:
        pub = ca_cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding
            pub.verify(certificado.signature, certificado.tbs_certificate_bytes,
                       padding.PKCS1v15(), certificado.signature_hash_algorithm)
        else:
            pub.verify(certificado.signature, certificado.tbs_certificate_bytes,
                       ec.ECDSA(certificado.signature_hash_algorithm))
    except Exception:
        return False
    return True


def _crear_certificado(username: str, device_id: str, cert_ca, clave_ca):
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ahora = datetime.now(timezone.utc)
    limite = min(ahora + timedelta(days=180), cert_ca.not_valid_after_utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, username),
        ]))
        .issuer_name(cert_ca.subject)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(minutes=5))
        .not_valid_after(limite)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(clave_ca, hashes.SHA256())
    )
    return clave, certificado


def emitir_certificados(
    *, ruta_usuarios: Path = RUTA_USUARIOS,
    directorio_destino: Path = DIRECTORIO_PRIVADO,
    ruta_ca_cert: Path = RUTA_CA_CERT,
    ruta_ca_key: Path = RUTA_CA_KEY,
    limite: int | None = None,
) -> dict[str, int]:
    """Genera pares RSA/certificados X.509 usando la CA YA existente.

    No modifica el certificado/clave de CA ni otros certificados del compañero.
    No sustituye pares existentes y rechaza archivos incoherentes.
    """
    cert_ca, clave_ca = _cargar_ca(ruta_ca_cert, ruta_ca_key)
    usuarios = cargar_usuarios(ruta_usuarios)
    preexistentes = [u for u in usuarios if u.get("origin") == "RF5"]
    if not preexistentes:
        raise ErrorRF5("No hay usuarios RF5. Ejecuta antes 'precargar'.")
    if limite is not None and (not isinstance(limite, int) or limite < 1):
        raise ErrorRF5("--limite debe ser >= 1")
    emitidos = 0
    reutilizados = 0
    for usuario in preexistentes[:limite]:
        username = usuario["username"]
        device_id = usuario["device_id"]
        ruta_key = directorio_destino / f"{username}.key"
        ruta_cert = directorio_destino / f"{username}.crt"
        if ruta_cert.exists() != ruta_key.exists():
            raise ErrorRF5(f"Par certificado/clave incompleto para {username}; revisar manualmente")
        if ruta_cert.exists():
            try:
                certificado = x509.load_pem_x509_certificate(ruta_cert.read_bytes())
                clave = serialization.load_pem_private_key(ruta_key.read_bytes(), password=None)
            except (ValueError, TypeError) as exc:
                raise ErrorRF5(f"Material PKI inválido para {username}") from exc
            if not _certificado_valido(certificado, clave, cert_ca, username, device_id):
                raise ErrorRF5(f"Certificado preexistente no válido para {username}; no se sobrescribe")
            reutilizados += 1
        else:
            clave, certificado = _crear_certificado(username, device_id, cert_ca, clave_ca)
            _escribir_atomico(ruta_key, clave.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"), privado=True)
            _escribir_atomico(ruta_cert, certificado.public_bytes(
                serialization.Encoding.PEM
            ).decode("ascii"), privado=False)
            emitidos += 1
        usuario["certificate_status"] = "issued"
        usuario["certificate_serial"] = str(certificado.serial_number)
        usuario["certificate_path"] = f"pki/clients/rf5/{username}.crt"
        usuario["public_key_fingerprint"] = hashlib.sha256(
            certificado.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        # Guardar progreso (permite retomar en caso de interrupción).
        _escribir_atomico(ruta_usuarios, json.dumps(usuarios, indent=2, ensure_ascii=False) + "\n", privado=True)
    return {"emitidos": emitidos, "reutilizados": reutilizados, "total_procesados": emitidos + reutilizados}
