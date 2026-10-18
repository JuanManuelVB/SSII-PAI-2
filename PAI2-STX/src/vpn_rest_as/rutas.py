"""API REST BYODSEC para consultar la VPN con credenciales de RF2.

No expone el token de administración de Access Server a clientes.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request

from src.rf2.rutas import _db, obtener_token, sesion_autenticada
from src.rf2.sesiones import revocar_token
from src.vpn_rest_as.autorizaciones import guardar_concesion, hay_concesion_de_otro_dispositivo
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
    if os.environ.get('BYODSEC_VPN_DEFAULT_DENY') != 'confirmed':
        raise HTTPException(503, 'No se ha verificado la política de acceso predeterminado bloqueado')
    if hay_concesion_de_otro_dispositivo(sesion['username'], sesion['device_id'], _db(request)):
        revocar_token(token, _db(request))
        raise HTTPException(409, 'La cuenta VPN tiene otra sesión de dispositivo activa')
    try:
        servicio.fijar_acceso(sesion['username'], permitido=True)
        guardar_concesion(token, sesion['username'], sesion['device_id'], _db(request))
    except Exception as exc:
        # Puede haberse aplicado deny=false antes de fallar el reinicio REST.
        # Compensamos por REST y revocamos el token RF2 sin esperar a caducidad.
        revocar_token(token, _db(request))
        try:
            servicio.fijar_acceso(sesion['username'], permitido=False)
            servicio.desconectar_usuario(sesion['username'])
        except AccessServerError:
            # El reconciliador debe volver a intentarlo; no anunciar éxito.
            pass
        raise HTTPException(503, 'La autorización VPN no está confirmada; token RF2 revocado') from exc
    return {'status': 'authorized', 'username': sesion['username'], 'device_id': sesion['device_id']}
