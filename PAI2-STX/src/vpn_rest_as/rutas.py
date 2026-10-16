"""API REST BYODSEC para consultar la VPN con credenciales de RF2.

No expone el token de administración de Access Server a clientes.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from src.rf2.rutas import _db, obtener_token
from src.vpn_rest_as.autorizaciones import guardar_concesion, autorizacion_vigente

from src.rf2.rutas import sesion_autenticada
from src.vpn_rest_as.client import AccessServerClient, AccessServerError, ConfigAccessServer

router = APIRouter(prefix='/api/v1/vpn', tags=['VPN REST'])


def proveedor() -> AccessServerClient:
    try:
        return AccessServerClient(ConfigAccessServer.desde_entorno())
    except AccessServerError as exc:
        raise HTTPException(503, 'Proveedor VPN no configurado') from exc


@router.get('/me')
def vpn_mia(sesion: dict = Depends(sesion_autenticada),
            servicio: AccessServerClient = Depends(proveedor)) -> dict:
    try:
        conexiones = servicio.conexiones_usuario(sesion['username'])
    except AccessServerError as exc:
        raise HTTPException(503, 'No se puede consultar el estado de la VPN') from exc
    return {
        'username': sesion['username'],
        'connected': bool(conexiones),
        'count': len(conexiones),
        'connections': [
            {'vpn_ip': c.get('virtual_ipv4_address'),
             'connected_since': c.get('connected_since'),
             'cipher': c.get('datachannel_cipher')}
            for c in conexiones
        ],
    }


@router.post('/authorize')
def autorizar_vpn(
    request: Request, sesion: dict = Depends(sesion_autenticada),
    token: str = Depends(obtener_token),
    servicio: AccessServerClient = Depends(proveedor),
) -> dict:
    """Una sesión RF2 válida habilita la cuenta VPN previamente provisionada.

    Condición de despliegue: todos los usuarios de Access Server deben
    empezar bloqueados (`deny=true`) y autologin deshabilitado.
    """
    import os
    if os.environ.get('BYODSEC_VPN_DEFAULT_DENY') != 'confirmed':
        raise HTTPException(503, 'No se ha verificado la política de acceso predeterminado bloqueado')
    try:
        servicio.fijar_acceso(sesion['username'], permitido=True)
    except AccessServerError as exc:
        raise HTTPException(503, 'No se pudo autorizar la VPN') from exc
    guardar_concesion(token, sesion['username'], sesion['device_id'], _db(request))
    return {'status': 'authorized', 'username': sesion['username']}
