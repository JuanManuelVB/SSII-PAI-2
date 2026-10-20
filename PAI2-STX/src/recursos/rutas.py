"""Recurso corporativo de demostración accesible SOLO con RF2/mTLS activo.

No depende de OpenVPN ni proporciona acceso a otras redes (camino A).
"""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.rf2.rutas import sesion_autenticada

router = APIRouter(prefix="/api/v1/resources", tags=["Recursos TLS"])


class MensajeSeguro(BaseModel):
    mensaje: str = Field(min_length=1, max_length=2048)


@router.get("/demo")
def recurso_protegido(sesion: dict[str, str] = Depends(sesion_autenticada)) -> dict[str, str]:
    """Datos corporativos de ejemplo, no disponibles sin sesión y mTLS."""
    return {
        "recurso": "documento-interno-demo",
        "contenido": "Acceso seguro BYODSEC autorizado",
        "username": sesion["username"],
        "role": sesion["role"],
    }


@router.post("/echo")
def procesar_mensaje(
    datos: MensajeSeguro,
    sesion: dict[str, str] = Depends(sesion_autenticada),
) -> dict[str, str | int]:
    """Prueba transmisión real Windows -> WSL -> Windows con identidad autenticada.

    Devuelve huella y tamaño sin registrar ni reflejar contenido sensible.
    """
    contenido = datos.mensaje.encode("utf-8")
    return {
        "status": "processed",
        "username": sesion["username"],
        "bytes": len(contenido),
        "sha256": hashlib.sha256(contenido).hexdigest(),
    }
