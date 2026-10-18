"""Endpoint opcional RF4 que pide la desconexión mediante REST nativa.

Importante: su función es efectuar la desconexión REST. No evita por sí
sola nuevas conexiones VPN: requerirá la política de acceso sincronizada.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from src.rf2.rutas import _db, obtener_token, sesion_autenticada
from src.rf2.sesiones import revocar_token
from src.rf4.auditoria import RUTA_AUDITORIA, registrar_cierre
from src.vpn_rest_as.client import AccessServerClient, AccessServerError
from src.vpn_rest_as.autorizaciones import bloquear_concesiones_usuario
from src.vpn_rest_as.rutas import proveedor

router = APIRouter(prefix='/api/v1/sessions', tags=['RF4 REST'])


@router.post('/abort', status_code=204)
def abortar_login_fallido(
    request: Request,
    sesion: dict = Depends(sesion_autenticada),
    token: str = Depends(obtener_token),
) -> Response:
    """Invalida un token RF2 si falló la autorización VPN en el cliente.

    No cambia permisos AS; el gateway debe compensar por REST los cambios
    parciales cuando ocurre un error en el proveedor VPN.
    """
    revocar_token(token, _db(request))
    return Response(status_code=204, headers={'Cache-Control': 'no-store'})


@router.post('/logout')
def logout_rest(
    request: Request,
    response: Response,
    sesion: dict = Depends(sesion_autenticada),
    token: str = Depends(obtener_token),
    servicio: AccessServerClient = Depends(proveedor),
) -> dict:
    # Fallo seguro: primero denegar futuras conexiones; después cortar las
    # actuales. Si falla REST, revocar igualmente las sesiones de aplicación.
    error_vpn = None
    try:
        servicio.fijar_acceso(sesion['username'], permitido=False)
    except AccessServerError:
        error_vpn = 'No se pudo bloquear la reconexión VPN'
    try:
        servicio.desconectar_usuario(sesion['username'])
        servicio.esperar_desconexion(sesion['username'])
    except AccessServerError:
        error_vpn = 'No se confirmó la desconexión VPN'

    # Independientemente de REST, invalidar todas las sesiones RF2 del usuario
    # para impedir reautorizaciones desde tokens antiguos.
    bloquear_concesiones_usuario(sesion['username'], _db(request))
    if not error_vpn:
        registrar_cierre(
            sesion['username'], sesion['device_id'],
            ruta=getattr(request.app.state, 'ruta_auditoria_rf4', RUTA_AUDITORIA),
        )
    else:
        # No registrar "session_closed" si el túnel no está confirmado.
        import json
        from datetime import datetime, timezone
        ruta = getattr(request.app.state, 'ruta_auditoria_rf4', RUTA_AUDITORIA)
        ruta.parent.mkdir(parents=True, exist_ok=True)
        with ruta.open('a', encoding='utf-8') as log:
            log.write(json.dumps({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event': 'session_web_revoked_vpn_unconfirmed',
                'username': sesion['username'], 'device_id': sesion['device_id'],
            }, ensure_ascii=False) + '\n')
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Connection'] = 'close'
    if error_vpn:
        raise HTTPException(503, error_vpn + '; sesiones BYODSEC revocadas')
    return {'status': 'closed', 'vpn_disconnect': 'verified', 'reconnect': 'denied'}
