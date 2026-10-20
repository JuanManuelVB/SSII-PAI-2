"""Gateway BYODSEC (RF2 + RF4 [+ VPN REST]); acceso público solo mediante mTLS.

Dos modos, elegidos al arrancar:

* ``BYODSEC_VPN_REST=1`` (laboratorio completo): RF2 + RF4 con cierre de la
  VPN por la API REST de OpenVPN Access Server (``src.vpn_rest_as``) y las
  rutas ``/api/v1/vpn/*``.
* Sin la variable: RF2 + RF4 solo de aplicación (revoca el token en SQLite).
  Es el modo que usan las pruebas que no necesitan Access Server.

El registro RF1 se sirve aparte (``src.gateway.ejecutar_registro``) porque
requiere TLS de servidor pero NO puede exigir certificado cliente antes del
emparejamiento.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.common.base_datos import inicializar_base_datos
from src.rf2.rutas import router as rf2_router
from src.recursos.rutas import router as recursos_router
from src.rf2.sesiones import inicializar_sesiones


@asynccontextmanager
async def lifespan(aplicacion: FastAPI):
    ruta = getattr(aplicacion.state, "ruta_base_datos", None)
    if ruta is None:
        inicializar_base_datos()
        inicializar_sesiones()
    else:
        inicializar_base_datos(ruta)
        inicializar_sesiones(ruta)
    yield


def crear_app(vpn_rest: bool | None = None) -> FastAPI:
    """Construye el gateway; por defecto el modo se lee de ``BYODSEC_VPN_REST``."""
    if vpn_rest is None:
        vpn_rest = os.environ.get("BYODSEC_VPN_REST") == "1"
    aplicacion = FastAPI(
        title="BYODSEC gateway: RF2 + RF4" + (" + VPN REST" if vpn_rest else ""),
        version="1.0.0",
        lifespan=lifespan,
    )
    aplicacion.include_router(rf2_router)
    aplicacion.include_router(recursos_router)
    if vpn_rest:
        from src.vpn_rest_as.rf4 import router as rf4_vpn_router
        from src.vpn_rest_as.rutas import router as vpn_router

        aplicacion.include_router(rf4_vpn_router)
        aplicacion.include_router(vpn_router)
    else:
        from src.rf4.rutas import router as rf4_router

        aplicacion.include_router(rf4_router)
    return aplicacion


app = crear_app()
