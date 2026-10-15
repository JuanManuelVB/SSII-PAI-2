"""Gestión de usuarios RF5 usando la base de datos común de RF1."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import secrets
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.common.base_datos import (
    RUTA_BASE_DATOS_POR_DEFECTO,
    ahora,
    conectar_base_datos,
    inicializar_base_datos,
)
from src.common.seguridad import crear_hash_contrasena

RAIZ = Path(__file__).resolve().parents[2]
RUTA_BASE_DATOS = RUTA_BASE_DATOS_POR_DEFECTO
DIRECTORIO_PRIVADO = RAIZ / "pki" / "clients" / "rf5"
RUTA_CREDENCIALES = DIRECTORIO_PRIVADO / "credenciales.csv"
RUTA_CA_CERT = RAIZ / "pki" / "ca" / "ca.crt"
RUTA_CA_KEY = RAIZ / "pki" / "ca" / "ca.key"

# Los tres roles utilizan exactamente los valores aceptados por SQLite y RF1.
# El prefijo solo se usa para construir nombres legibles de cuentas y
# dispositivos; el rol completo que se guarda en la tabla es la clave.
PERFILES = {"PDI": "pdi", "PAS": "pas", "INVESTIGADOR": "inv"}
CAMPOS_CREDENCIALES = ("username", "password", "role", "device_id")


class ErrorRF5(ValueError):
    """Error explícito que evita ocultar fallos de configuración o datos."""


def _escribir_atomico(ruta: Path, texto: str, *, privado: bool) -> None:
    """Escribe un archivo temporal y lo sustituye solo cuando está completo."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporal = tempfile.mkstemp(prefix=".rf5-", dir=ruta.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as archivo:
            archivo.write(texto)
            archivo.flush()
            os.fsync(archivo.fileno())
        os.chmod(temporal, 0o600 if privado else 0o644)
        os.replace(temporal, ruta)
    finally:
        if os.path.exists(temporal):
            os.unlink(temporal)


def reparto_roles(total: int) -> dict[str, int]:
    """Reparte el total de usuarios de forma equilibrada entre los tres roles."""
    if not isinstance(total, int) or isinstance(total, bool) or total < 3 or total > 3000:
        raise ErrorRF5("El total debe estar entre 3 y 3000")
    base, resto = divmod(total, len(PERFILES))
    return {
        rol: base + (indice < resto)
        for indice, rol in enumerate(PERFILES)
    }


def _leer_credenciales(ruta: Path = RUTA_CREDENCIALES) -> list[dict[str, str]]:
    """Lee el CSV local que permite lanzar pruebas de carga."""
    if not ruta.exists():
        return []
    with ruta.open("r", encoding="utf-8", newline="") as archivo:
        lector = csv.DictReader(archivo)
        if tuple(lector.fieldnames or []) != CAMPOS_CREDENCIALES:
            raise ErrorRF5("CSV de credenciales previo inválido; no será sobrescrito")
        registros = list(lector)
    nombres = [registro["username"] for registro in registros]
    if len(nombres) != len(set(nombres)):
        raise ErrorRF5("CSV de credenciales contiene usernames duplicados")
    return registros


def _csv_credenciales(credenciales: list[dict[str, str]]) -> str:
    """Convierte las credenciales temporales a CSV."""
    salida = io.StringIO(newline="")
    escritor = csv.DictWriter(salida, fieldnames=CAMPOS_CREDENCIALES)
    escritor.writeheader()
    escritor.writerows(credenciales)
    return salida.getvalue()


def _usuarios_rf5(conexion: sqlite3.Connection) -> list[sqlite3.Row]:
    """Obtiene solo usuarios creados por RF5, sin devolver hashes."""
    return conexion.execute(
        """
        SELECT username, role, status, created_at
        FROM users
        WHERE origin = 'RF5'
        ORDER BY username
        """
    ).fetchall()


def precargar_usuarios(
    total: int = 300,
    *,
    ruta_base_datos: Path = RUTA_BASE_DATOS,
    ruta_credenciales: Path = RUTA_CREDENCIALES,
) -> dict[str, object]:
    """Crea cuentas RF5 en SQLite de forma idempotente.

    SQLite es la fuente oficial de autenticación. El CSV solo conserva las
    contraseñas temporales necesarias para ejecutar el benchmark local.
    """
    # Primero validamos y calculamos el reparto antes de tocar la base de
    # datos. Así un valor inválido no puede dejar cambios parciales.
    reparto = reparto_roles(total)
    inicializar_base_datos(ruta_base_datos)
    # El CSV no autentica a nadie: únicamente permite conocer las contraseñas
    # aleatorias del laboratorio para poder lanzar un benchmark posteriormente.
    credenciales = _leer_credenciales(ruta_credenciales)
    nombres_credenciales = {registro["username"] for registro in credenciales}
    nuevas_credenciales: list[dict[str, str]] = []
    creados = 0

    with conectar_base_datos(ruta_base_datos) as conexion:
        # Se consultan también las cuentas MANUAL. Esto permite detectar una
        # colisión antes de intentar insertar y garantiza que RF5 no las
        # sobrescriba accidentalmente.
        existentes = {
            fila["username"]: fila
            for fila in conexion.execute(
                "SELECT username, role, origin FROM users"
            ).fetchall()
        }
        for rol, prefijo in PERFILES.items():
            for numero in range(1, reparto[rol] + 1):
                username = f"rf5_{prefijo}_{numero:03d}"
                device_id = f"rf5-{prefijo}-{numero:03d}-dev01"
                existente = existentes.get(username)
                if existente:
                    if existente["origin"] != "RF5":
                        raise ErrorRF5(
                            f"Colisión: {username} ya pertenece a otra fuente"
                        )
                    if existente["role"] != rol:
                        raise ErrorRF5(f"Colisión de rol para el usuario {username}")
                    continue
                if username in nombres_credenciales:
                    raise ErrorRF5(f"Existen credenciales sin cuenta para {username}")

                # La contraseña solo vive en memoria durante esta operación.
                # SQLite recibe exclusivamente su hash scrypt.
                password = secrets.token_urlsafe(24)
                marca_tiempo = ahora()
                conexion.execute(
                    """
                    INSERT INTO users
                    (username, password_hash, role, status, origin, created_at, updated_at)
                    VALUES (?, ?, ?, 'active', 'RF5', ?, ?)
                    """,
                    (
                        username,
                        crear_hash_contrasena(password),
                        rol,
                        marca_tiempo,
                        marca_tiempo,
                    ),
                )
                nuevas_credenciales.append(
                    {
                        "username": username,
                        "password": password,
                        "role": rol,
                        "device_id": device_id,
                    }
                )
                creados += 1

    # El commit de SQLite ya ha finalizado. Solo entonces actualizamos el CSV,
    # usando una sustitución atómica para no dejar un archivo truncado.
    if nuevas_credenciales:
        _escribir_atomico(
            ruta_credenciales,
            _csv_credenciales(credenciales + nuevas_credenciales),
            privado=True,
        )

    # Se vuelve a consultar el total real, en lugar de calcularlo con el
    # contador local, porque la base puede contener cuentas RF5 previas.
    with conectar_base_datos(ruta_base_datos) as conexion:
        total_rf5 = conexion.execute(
            "SELECT COUNT(*) FROM users WHERE origin = 'RF5'"
        ).fetchone()[0]

    return {
        "nuevos": creados,
        "total_rf5": total_rf5,
        "reparto_solicitado": reparto,
        "ruta_base_datos": str(ruta_base_datos),
        "ruta_credenciales_privadas": str(ruta_credenciales),
    }


def consultar_perfil(
    username: str,
    ruta_base_datos: Path = RUTA_BASE_DATOS,
) -> dict[str, str] | None:
    """Devuelve metadatos del usuario RF5 activo, sin hash ni contraseña."""
    inicializar_base_datos(ruta_base_datos)
    with conectar_base_datos(ruta_base_datos) as conexion:
        usuario = conexion.execute(
            """
            SELECT username, role
            FROM users
            WHERE username = ? AND origin = 'RF5' AND status = 'active'
            """,
            (username,),
        ).fetchone()
        if not usuario:
            return None
        # El emparejamiento es opcional: una cuenta puede existir antes de que
        # se emita su certificado cliente.
        dispositivo = conexion.execute(
            """
            SELECT device_id, certificate_serial, status, certificate_path
            FROM device_pairings
            WHERE username = ? AND status = 'active'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (username,),
        ).fetchone()
    return {
        "username": usuario["username"],
        "role": usuario["role"],
        "device_id": dispositivo["device_id"] if dispositivo else "",
        "certificate_serial": dispositivo["certificate_serial"] if dispositivo else "",
        "certificate_status": "issued" if dispositivo else "pending",
    }


def resumen_usuarios(
    ruta_base_datos: Path = RUTA_BASE_DATOS,
) -> dict[str, object]:
    """Calcula estadísticas RF5 sin exponer datos sensibles."""
    inicializar_base_datos(ruta_base_datos)
    with conectar_base_datos(ruta_base_datos) as conexion:
        usuarios = _usuarios_rf5(conexion)
        emitidos = conexion.execute(
            """
            SELECT COUNT(*)
            FROM device_pairings
            WHERE username IN (SELECT username FROM users WHERE origin = 'RF5')
            """
        ).fetchone()[0]
    return {
        "total_rf5": len(usuarios),
        "por_rol": dict(Counter(usuario["role"] for usuario in usuarios)),
        "certificados_emitidos": emitidos,
        "usuarios_activos": sum(usuario["status"] == "active" for usuario in usuarios),
    }


def _cargar_ca(ruta_cert: Path, ruta_key: Path):
    """Carga y valida la CA existente sin crear ni sustituir otra."""
    if not ruta_cert.is_file() or not ruta_key.is_file():
        raise ErrorRF5("Falta la CA: pki/ca/ca.crt y/o pki/ca/ca.key")
    try:
        certificado = x509.load_pem_x509_certificate(ruta_cert.read_bytes())
        clave = serialization.load_pem_private_key(ruta_key.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise ErrorRF5("La CA no tiene formato PEM válido o la clave está cifrada") from exc
    if not isinstance(clave, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ErrorRF5("La CA debe usar clave RSA o EC")
    if not secrets.compare_digest(
        certificado.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        clave.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    ):
        raise ErrorRF5("La clave privada de CA no corresponde al certificado")
    try:
        restricciones = certificado.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise ErrorRF5("La CA no declara BasicConstraints") from exc
    if not restricciones.ca:
        raise ErrorRF5("El certificado de firma no es de CA")
    ahora_utc = datetime.now(timezone.utc)
    if not (certificado.not_valid_before_utc <= ahora_utc <= certificado.not_valid_after_utc):
        raise ErrorRF5("El certificado de CA no está vigente")
    return certificado, clave


def _crear_certificado(username: str, device_id: str, cert_ca, clave_ca):
    """Genera una clave RSA y un certificado cliente de laboratorio."""
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ahora_utc = datetime.now(timezone.utc)
    limite = min(ahora_utc + timedelta(days=180), cert_ca.not_valid_after_utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, device_id),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, username),
                ]
            )
        )
        .issuer_name(cert_ca.subject)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora_utc - timedelta(minutes=5))
        .not_valid_after(limite)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(clave_ca, hashes.SHA256())
    )
    return clave, certificado


def emitir_certificados(
    *,
    ruta_base_datos: Path = RUTA_BASE_DATOS,
    directorio_destino: Path = DIRECTORIO_PRIVADO,
    ruta_ca_cert: Path = RUTA_CA_CERT,
    ruta_ca_key: Path = RUTA_CA_KEY,
    limite: int | None = None,
) -> dict[str, int]:
    """Emite certificados para usuarios RF5 y registra sus emparejamientos."""
    # La CA se valida antes de crear directorios o claves nuevas. Si falta o
    # no corresponde con su clave privada, la operación termina sin cambios.
    cert_ca, clave_ca = _cargar_ca(ruta_ca_cert, ruta_ca_key)
    inicializar_base_datos(ruta_base_datos)
    if limite is not None and (not isinstance(limite, int) or limite < 1):
        raise ErrorRF5("--limite debe ser >= 1")

    with conectar_base_datos(ruta_base_datos) as conexion:
        usuarios = conexion.execute(
            """
            SELECT username
            FROM users
            WHERE origin = 'RF5' AND status = 'active'
            ORDER BY username
            """
        ).fetchall()

    if not usuarios:
        raise ErrorRF5("No hay usuarios RF5. Ejecuta antes 'precargar'.")

    emitidos = 0
    reutilizados = 0
    directorio_destino.mkdir(parents=True, exist_ok=True)
    # El corte permite emitir solo una muestra durante las pruebas sin
    # alterar el conjunto de usuarios almacenado.
    for fila in usuarios[:limite]:
        username = fila["username"]
        perfil = username.split("_")[1]
        numero = username.split("_")[2]
        device_id = f"rf5-{perfil}-{numero}-dev01"
        ruta_key = directorio_destino / f"{username}.key"
        ruta_cert = directorio_destino / f"{username}.crt"

        # Nunca se debe completar automáticamente un par incompleto: podría
        # asociar una clave nueva a un certificado que ya estaba desplegado.
        if ruta_cert.exists() != ruta_key.exists():
            raise ErrorRF5(f"Par certificado/clave incompleto para {username}")

        if ruta_cert.exists():
            try:
                certificado = x509.load_pem_x509_certificate(ruta_cert.read_bytes())
                clave = serialization.load_pem_private_key(
                    ruta_key.read_bytes(), password=None
                )
            except (ValueError, TypeError) as exc:
                raise ErrorRF5(f"Material PKI inválido para {username}") from exc
            if certificado.issuer != cert_ca.subject:
                raise ErrorRF5(f"Certificado no emitido por la CA configurada: {username}")
            reutilizados += 1
        else:
            # La clave se genera localmente y se firma con la CA corporativa.
            # En un BYOD real esta clave debe generarse en el dispositivo,
            # no en el gateway.
            clave, certificado = _crear_certificado(
                username, device_id, cert_ca, clave_ca
            )
            _escribir_atomico(
                ruta_key,
                clave.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode("ascii"),
                privado=True,
            )
            _escribir_atomico(
                ruta_cert,
                certificado.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                privado=False,
            )
            emitidos += 1

        # La huella identifica la clave pública, no la contraseña ni la clave
        # privada. RF1 puede usarla para vincular el certificado al dispositivo.
        huella = hashlib.sha256(
            certificado.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        # La inserción es idempotente por device_id: si el certificado ya
        # existía, se actualizan sus metadatos sin crear otra fila.
        with conectar_base_datos(ruta_base_datos) as conexion:
            conexion.execute(
                """
                INSERT INTO device_pairings
                (device_id, username, public_key_fingerprint, certificate_serial,
                 certificate_path, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
                ON CONFLICT(device_id) DO UPDATE SET
                    public_key_fingerprint = excluded.public_key_fingerprint,
                    certificate_serial = excluded.certificate_serial,
                    certificate_path = excluded.certificate_path,
                    status = 'active'
                """,
                (
                    device_id,
                    username,
                    huella,
                    str(certificado.serial_number),
                    f"pki/clients/rf5/{username}.crt",
                    ahora(),
                ),
            )

    return {
        "emitidos": emitidos,
        "reutilizados": reutilizados,
        "total_procesados": emitidos + reutilizados,
    }
