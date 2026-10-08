"""API REST de RF1 para registrar dispositivos y asociarlos con la PKI."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

RAIZ = Path(__file__).resolve().parents[2]
DIRECTORIO_DATOS = RAIZ / "data"
DIRECTORIO_PKI = RAIZ / "pki"
RUTA_BASE_DATOS = DIRECTORIO_DATOS / "rf1.sqlite3"
RUTA_AUDITORIA = RAIZ / "evidencias" / "logs" / "rf1-audit.jsonl"
RUTA_CERTIFICADO_CA = DIRECTORIO_PKI / "ca" / "ca.crt"
RUTA_CLAVE_CA = DIRECTORIO_PKI / "ca" / "ca.key"
DIRECTORIO_CERTIFICADOS_CLIENTE = DIRECTORIO_PKI / "clients"
RUTA_USUARIOS = DIRECTORIO_DATOS / "usuarios_precargados" / "usuarios.json"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
registrador = logging.getLogger(__name__)

aplicacion = FastAPI(title="PAI2-STX RF1 API", version="0.1.0")
# Alias de compatibilidad para el comando estándar de Uvicorn.
app = aplicacion


class SolicitudRegistro(BaseModel):
    """Datos recibidos para registrar un dispositivo BYOD.

    Los nombres de los atributos se mantienen en inglés porque forman parte
    del contrato JSON público de la API.
    """

    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=256)
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    public_key: str = Field(min_length=64, max_length=8192)


class RespuestaRegistro(BaseModel):
    """Datos devueltos después de emitir el certificado del dispositivo."""

    device_id: str
    username: str
    certificate: str
    ca_certificate: str
    certificate_serial: str
    status: str


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


def _auditar(evento: str, **campos: str) -> None:
    """Escribe un evento estructurado sin registrar contraseñas ni claves."""
    RUTA_AUDITORIA.parent.mkdir(parents=True, exist_ok=True)
    registro = {"timestamp": _ahora(), "event": evento, **campos}
    with RUTA_AUDITORIA.open("a", encoding="utf-8") as archivo:
        archivo.write(json.dumps(registro, sort_keys=True) + "\n")


def _crear_hash_contrasena(contrasena: str, sal: bytes) -> str:
    resumen = hashlib.scrypt(contrasena.encode(), salt=sal, n=2**14, r=8, p=1)
    return f"scrypt${sal.hex()}${resumen.hex()}"


def _verificar_contrasena(contrasena: str, codificada: str) -> bool:
    try:
        algoritmo, sal_hex, resumen_hex = codificada.split("$")
        if algoritmo != "scrypt":
            return False
        candidata = _crear_hash_contrasena(contrasena, bytes.fromhex(sal_hex))
        return secrets.compare_digest(candidata, f"scrypt${sal_hex}${resumen_hex}")
    except (ValueError, TypeError):
        return False


def _conectar() -> sqlite3.Connection:
    DIRECTORIO_DATOS.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(RUTA_BASE_DATOS)
    conexion.row_factory = sqlite3.Row
    return conexion


def _inicializar_base_datos() -> None:
    """Crea la tabla de emparejamientos si todavía no existe."""
    with _conectar() as conexion:
        conexion.execute(
            """
            CREATE TABLE IF NOT EXISTS device_pairings (
                device_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                public_key_fingerprint TEXT NOT NULL UNIQUE,
                certificate_serial TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('active', 'revoked'))
            )
            """
        )


def _cargar_usuario(nombre_usuario: str) -> dict[str, str] | None:
    """Busca una cuenta creada manualmente en el fichero de usuarios."""
    if not RUTA_USUARIOS.exists():
        return None
    usuarios = json.loads(RUTA_USUARIOS.read_text(encoding="utf-8"))
    return next(
        (usuario for usuario in usuarios if usuario.get("username") == nombre_usuario),
        None,
    )


def _analizar_clave_publica(valor: str):
    """Valida que la clave recibida sea RSA y tenga una longitud suficiente."""
    try:
        clave = serialization.load_pem_public_key(valor.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise HTTPException(
            status_code=422,
            detail="public_key must be a valid PEM public key",
        ) from exc
    if not isinstance(clave, rsa.RSAPublicKey):
        raise HTTPException(status_code=422, detail="only RSA public keys are supported")
    if clave.key_size < 2048:
        raise HTTPException(status_code=422, detail="RSA public key must be at least 2048 bits")
    return clave


def _emitir_certificado(
    nombre_usuario: str, identificador_dispositivo: str, clave_publica
) -> tuple[str, str]:
    """Firma un certificado cliente con la CA corporativa configurada."""
    if not RUTA_CERTIFICADO_CA.exists() or not RUTA_CLAVE_CA.exists():
        raise HTTPException(status_code=503, detail="corporate CA is not configured")
    try:
        clave_ca = serialization.load_pem_private_key(
            RUTA_CLAVE_CA.read_bytes(), password=None
        )
        certificado_ca = x509.load_pem_x509_certificate(
            RUTA_CERTIFICADO_CA.read_bytes()
        )
    except (ValueError, OSError) as exc:
        registrador.exception("No se puede cargar la CA corporativa")
        raise HTTPException(
            status_code=503, detail="corporate CA cannot be loaded"
        ) from exc

    numero_serie = x509.random_serial_number()
    certificado = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, identificador_dispositivo),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, nombre_usuario),
                ]
            )
        )
        .issuer_name(certificado_ca.subject)
        .public_key(clave_publica)
        .serial_number(numero_serie)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(clave_ca, hashes.SHA256())
    )
    DIRECTORIO_CERTIFICADOS_CLIENTE.mkdir(parents=True, exist_ok=True)
    ruta_certificado = (
        DIRECTORIO_CERTIFICADOS_CLIENTE / f"{identificador_dispositivo}.crt"
    )
    contenido = certificado.public_bytes(serialization.Encoding.PEM)
    ruta_certificado.write_bytes(contenido)
    return contenido.decode(), str(numero_serie)


@aplicacion.on_event("startup")
def iniciar_aplicacion() -> None:
    _inicializar_base_datos()


@aplicacion.get("/health")
def comprobar_salud() -> dict[str, str]:
    return {"status": "ok"}


@aplicacion.post(
    "/api/v1/devices/register",
    response_model=RespuestaRegistro,
    status_code=status.HTTP_201_CREATED,
)
def registrar_dispositivo(solicitud: SolicitudRegistro) -> RespuestaRegistro:
    """Registra el dispositivo y vincula su clave pública al usuario."""
    usuario = _cargar_usuario(solicitud.username)
    if usuario is None or usuario.get("status") != "active" or not _verificar_contrasena(
        solicitud.password, usuario.get("password_hash", "")
    ):
        _auditar(
            "registration_rejected",
            username=solicitud.username,
            device_id=solicitud.device_id,
            reason="invalid_credentials",
        )
        raise HTTPException(status_code=401, detail="invalid credentials")

    clave_publica = _analizar_clave_publica(solicitud.public_key)
    huella = hashlib.sha256(
        clave_publica.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()

    try:
        with _conectar() as conexion:
            if conexion.execute(
                "SELECT 1 FROM device_pairings WHERE device_id = ? AND status = 'active'",
                (solicitud.device_id,),
            ).fetchone():
                _auditar(
                    "registration_rejected",
                    username=solicitud.username,
                    device_id=solicitud.device_id,
                    reason="device_already_registered",
                )
                raise HTTPException(status_code=409, detail="device is already registered")
            if conexion.execute(
                "SELECT 1 FROM device_pairings WHERE public_key_fingerprint = ? AND status = 'active'",
                (huella,),
            ).fetchone():
                _auditar(
                    "registration_rejected",
                    username=solicitud.username,
                    device_id=solicitud.device_id,
                    reason="public_key_already_registered",
                )
                raise HTTPException(status_code=409, detail="public key is already registered")

            certificado, numero_serie = _emitir_certificado(
                solicitud.username, solicitud.device_id, clave_publica
            )
            conexion.execute(
                """
                INSERT INTO device_pairings
                (device_id, username, public_key_fingerprint, certificate_serial, created_at, status)
                VALUES (?, ?, ?, ?, ?, 'active')
                """,
                (
                    solicitud.device_id,
                    solicitud.username,
                    huella,
                    numero_serie,
                    _ahora(),
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="device or public key is already registered",
        ) from exc

    _auditar(
        "device_registered",
        username=solicitud.username,
        device_id=solicitud.device_id,
        certificate_serial=numero_serie,
    )
    return RespuestaRegistro(
        device_id=solicitud.device_id,
        username=solicitud.username,
        certificate=certificado,
        ca_certificate=RUTA_CERTIFICADO_CA.read_text(encoding="ascii"),
        certificate_serial=numero_serie,
        status="registered",
    )
