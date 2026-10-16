"""Endpoint RF4: cierre explícito de la sesión autenticada."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from src.rf2.rutas import _db, obtener_token, sesion_autenticada
from src.rf4.auditoria import RUTA_AUDITORIA, registrar_cierre
from src.rf4.cierre import revocar_sesion

router = APIRouter(prefix="/api/v1/sessions", tags=["RF4"])


@router.post("/logout")
def logout(request: Request, response: Response,
           sesion: dict[str, str] = Depends(sesion_autenticada),
           token: str = Depends(obtener_token)) -> dict[str, str]:
    if not revocar_sesion(token, _db(request)):
        raise HTTPException(401, "sesión no válida")
    ruta_auditoria = getattr(request.app.state, "ruta_auditoria_rf4", RUTA_AUDITORIA)
    registrar_cierre(sesion["username"], sesion["device_id"], ruta=ruta_auditoria)
    # HTTP/1.1: pide cerrar el transporte tras enviar la respuesta.
    # El cliente debe cerrar además su SSL socket y desmontar la VPN si existe.
    response.headers["Connection"] = "close"
    response.headers["Cache-Control"] = "no-store"
    return {"status": "closed"}
