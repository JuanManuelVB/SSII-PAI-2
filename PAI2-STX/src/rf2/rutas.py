"""Endpoints RF2: desafíos, login y consulta de sesión."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from src.server.tls import obtener_huella_clave_certificado
from pydantic import BaseModel, Field

from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO
from src.common.config_tls import RUTA_CERTIFICADO_CA
from src.common.auditoria import RUTA_AUDITORIA_ACCESOS, registrar_evento
from src.rf2.autenticacion import AutenticacionRechazada, autenticar
from src.rf2.sesiones import crear_desafio, crear_sesion, validar_sesion

router = APIRouter(prefix="/api/v1/sessions", tags=["RF2"])


def _ruta_auditoria(request: Request) -> Path:
    return getattr(request.app.state, "ruta_auditoria_accesos", RUTA_AUDITORIA_ACCESOS)


class SolicitudDesafio(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")


class SolicitudLogin(SolicitudDesafio):
    password: str = Field(min_length=1, max_length=256)
    nonce: str = Field(min_length=32, max_length=128)
    certificate: str = Field(min_length=100, max_length=8192)
    signature: str = Field(min_length=32, max_length=2048)


def _db(request: Request) -> Path:
    return Path(getattr(request.app.state, "ruta_base_datos", RUTA_BASE_DATOS_POR_DEFECTO))


def exigir_https(request: Request) -> None:
    # La API NO debe utilizarse con `uvicorn src.gateway.app:app` por HTTP.
    if request.scope.get("scheme") != "https" or not request.scope.get("mtls_client_cert_der"):
        raise HTTPException(403, "Se requiere HTTPS con mTLS autenticado")


def obtener_token(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "sesión no válida", headers={"WWW-Authenticate": "Bearer"})
    token = authorization[7:]
    if not token or len(token) > 512 or any(c.isspace() for c in token):
        raise HTTPException(401, "sesión no válida")
    return token


def sesion_autenticada(request: Request, token: str = Depends(obtener_token)) -> dict[str, str]:
    exigir_https(request)
    sesion = validar_sesion(token, _db(request))
    if sesion is None:
        raise HTTPException(401, "sesión no válida")
    # Protección ante el robo de un bearer token: debe coincidir también el
    # certificado realmente negociado por TLS (no una cabecera falsificable).
    try:
        certificado_tls = x509.load_der_x509_certificate(request.scope["mtls_client_cert_der"])
        huella_tls = obtener_huella_clave_certificado(request.scope["mtls_client_cert_der"])
    except ValueError:
        raise HTTPException(401, "sesión no válida") from None
    if (str(certificado_tls.serial_number) != sesion["certificate_serial"]
            or huella_tls != sesion["public_key_fingerprint"]):
        raise HTTPException(401, "sesión no válida")
    return sesion


@router.post("/challenge")
def desafio(solicitud: SolicitudDesafio, request: Request) -> dict[str, str]:
    exigir_https(request)
    nonce, expiracion = crear_desafio(solicitud.username, solicitud.device_id, _db(request))
    return {"nonce": nonce, "expires_at": expiracion}


@router.post("/login")
def login(solicitud: SolicitudLogin, request: Request) -> dict[str, str]:
    exigir_https(request)
    ruta_ca = Path(getattr(request.app.state, "ruta_ca", RUTA_CERTIFICADO_CA))
    ruta_revocados = getattr(request.app.state, "ruta_revocados", ruta_ca.parent / "revoked.json")
    # Se exige que el certificado enviado coincida exactamente con el que
    # OpenSSL ha validado en la negociación mTLS.
    def _rechazar(mensaje: str, motivo: str):
        registrar_evento("login_failed", outcome="failure", username=solicitud.username,
                         device_id=solicitud.device_id, reason=motivo, source="RF2",
                         ruta=_ruta_auditoria(request))
        return HTTPException(401, mensaje)

    try:
        certificado_tls = x509.load_der_x509_certificate(request.scope["mtls_client_cert_der"])
        certificado_enviado = x509.load_pem_x509_certificate(solicitud.certificate.encode("ascii"))
        if certificado_tls.fingerprint(hashes.SHA256()) != certificado_enviado.fingerprint(hashes.SHA256()):
            raise _rechazar("certificado de dispositivo no autorizado", "certificado_mtls_no_coincide")
    except (ValueError, UnicodeError):
        raise _rechazar("certificado de dispositivo no autorizado", "certificado_ilegible") from None
    try:
        serial = autenticar(
            username=solicitud.username, password=solicitud.password, device_id=solicitud.device_id,
            nonce=solicitud.nonce, certificate=solicitud.certificate, signature=solicitud.signature,
            ruta_base_datos=_db(request), ruta_ca=ruta_ca, ruta_revocados=ruta_revocados,
        )
    except AutenticacionRechazada:
        raise _rechazar("credenciales o dispositivo no autorizados", "credenciales_o_dispositivo") from None
    token, expiracion = crear_sesion(solicitud.username, solicitud.device_id, serial, _db(request))
    registrar_evento("login_succeeded", outcome="success", username=solicitud.username,
                     device_id=solicitud.device_id, source="RF2", ruta=_ruta_auditoria(request))
    return {"access_token": token, "token_type": "bearer", "expires_at": expiracion}


@router.get("/me")
def consultar_sesion(sesion: dict[str, str] = Depends(sesion_autenticada)) -> dict[str, str]:
    return {"username": sesion["username"], "device_id": sesion["device_id"], "role": sesion["role"], "expires_at": sesion["expires_at"]}
