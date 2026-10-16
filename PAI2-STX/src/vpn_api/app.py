"""API REST de administración de VPN para uso exclusivo por el backend RF4.

Iniciar con: python -m src.vpn_api.ejecutar
Nunca publicar este servicio a Internet ni permitir acceso de usuarios BYOD.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from src.vpn_api.openvpn_manager import (
    ClienteVPNNoEncontrado, IdentidadVPNNoCoincide, OpenVPNManager,
    OpenVPNManagerError,
)
from src.vpn_api.seguridad import exigir_servicio, leer_token

@asynccontextmanager
async def lifespan(_app: FastAPI):
    leer_token()
    yield


app = FastAPI(
    title='BYODSEC - Control VPN interno',
    version='1.0.0',
    docs_url=None, redoc_url=None, openapi_url=None,
    dependencies=[Depends(exigir_servicio)],
    lifespan=lifespan,
)


def _manager() -> OpenVPNManager:
    return OpenVPNManager(os.environ.get('BYODSEC_OPENVPN_SOCKET', '/run/byodsec-vpn/management.sock'))


def _fallo(exc: Exception) -> HTTPException:
    if isinstance(exc, ClienteVPNNoEncontrado):
        return HTTPException(404, 'Conexión no encontrada')
    if isinstance(exc, IdentidadVPNNoCoincide):
        return HTTPException(409, 'No coincide el certificado esperado')
    return HTTPException(503, 'OpenVPN no disponible o no pudo confirmar la operación')


class DisconnectRequest(BaseModel):
    client_id: int = Field(ge=0)
    expected_common_name: str = Field(min_length=1, max_length=256)


@app.get('/api/v1/vpn/status')
def status(manager: Annotated[OpenVPNManager, Depends(_manager)]):
    try:
        conns = manager.connections()
    except OpenVPNManagerError as exc:
        raise _fallo(exc) from exc
    return {'server': 'available', 'connected_clients': len(conns)}


@app.get('/api/v1/vpn/connections')
def connections(manager: Annotated[OpenVPNManager, Depends(_manager)]):
    try:
        conns = manager.connections()
    except OpenVPNManagerError as exc:
        raise _fallo(exc) from exc
    return {'connections': [conn.public() for conn in conns]}


@app.post('/internal/vpn/disconnect')
def disconnect(body: DisconnectRequest, manager: Annotated[OpenVPNManager, Depends(_manager)]):
    try:
        return manager.disconnect(body.client_id, body.expected_common_name)
    except (ClienteVPNNoEncontrado, IdentidadVPNNoCoincide, OpenVPNManagerError) as exc:
        raise _fallo(exc) from exc
