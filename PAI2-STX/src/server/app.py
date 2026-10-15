"""API REST de RF1 para registrar dispositivos y asociarlos con la PKI."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from src.common.base_datos import (
    ahora,
    conectar_base_datos,
    inicializar_base_datos,
)
from src.common.seguridad import verificar_contrasena

RAIZ = Path(__file__).resolve().parents[2]
DIRECTORIO_DATOS = RAIZ / "data"
DIRECTORIO_PKI = RAIZ / "pki"
RUTA_AUDITORIA = RAIZ / "evidencias" / "logs" / "rf1-audit.jsonl"
RUTA_CERTIFICADO_CA = DIRECTORIO_PKI / "ca" / "ca.crt"
RUTA_CLAVE_CA = DIRECTORIO_PKI / "ca" / "ca.key"
DIRECTORIO_CERTIFICADOS_CLIENTE = DIRECTORIO_PKI / "clients"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
registrador = logging.getLogger(__name__)

@asynccontextmanager
async def ciclo_de_vida(_aplicacion: FastAPI):
    """Inicializa la base de datos cuando FastAPI crea la aplicación."""
    _inicializar_base_datos()
    yield


aplicacion = FastAPI(
    title="PAI2-STX RF1 API",
    version="0.1.0",
    lifespan=ciclo_de_vida,
)
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


def _auditar(evento: str, **campos: str) -> None:
    """Escribe un evento estructurado sin registrar contraseñas ni claves."""
    RUTA_AUDITORIA.parent.mkdir(parents=True, exist_ok=True)
    registro = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": evento,
        **campos,
    }
    with RUTA_AUDITORIA.open("a", encoding="utf-8") as archivo:
        archivo.write(json.dumps(registro, sort_keys=True) + "\n")


def _ahora() -> str:
    """Mantiene el nombre interno anterior usando la utilidad común."""
    return ahora()


# Estos alias conservan la compatibilidad con los tests y módulos existentes
# mientras RF1 pasa a utilizar las implementaciones centralizadas.
_conectar = conectar_base_datos
_inicializar_base_datos = inicializar_base_datos
_verificar_contrasena = verificar_contrasena


def _cargar_usuario(nombre_usuario: str) -> dict[str, str] | None:
    """Busca una cuenta creada manualmente en la base de datos."""
    with conectar_base_datos() as conexion:
        fila = conexion.execute(
            """
            SELECT username, password_hash, role, status
            FROM users
            WHERE username = ?
            """,
            (nombre_usuario,),
        ).fetchone()
    return dict(fila) if fila else None


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
) -> tuple[str, str, str]:
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

    # El certificado cliente solo sirve para autenticación de cliente. Además,
    # nunca debe durar más que la CA que lo firma.
    numero_serie = x509.random_serial_number()
    inicio = datetime.now(timezone.utc) - timedelta(minutes=5)
    fin = min(inicio + timedelta(days=365), certificado_ca.not_valid_after_utc)
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
        .not_valid_before(inicio)
        .not_valid_after(fin)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
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
    ruta_relativa = ruta_certificado.relative_to(RAIZ).as_posix()
    return contenido.decode(), str(numero_serie), ruta_relativa


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

    ruta_certificado_emitido: Path | None = None
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

            certificado, numero_serie, ruta_certificado = _emitir_certificado(
                solicitud.username, solicitud.device_id, clave_publica
            )
            ruta_certificado_emitido = RAIZ / ruta_certificado
            conexion.execute(
                """
                INSERT INTO device_pairings
                (device_id, username, public_key_fingerprint, certificate_serial,
                 certificate_path, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
                """,
                (
                    solicitud.device_id,
                    solicitud.username,
                    huella,
                    numero_serie,
                    ruta_certificado,
                    _ahora(),
                ),
            )
    except sqlite3.IntegrityError as exc:
        if ruta_certificado_emitido is not None:
            ruta_certificado_emitido.unlink(missing_ok=True)
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
