"""Alternativa de gateway (no sustituye src.gateway.app del equipo).

Servir EXCLUSIVAMENTE con el arranque TLS1.3/mTLS en ejecutar.py.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI

from src.rf2.rutas import router as rf2_router
from src.rf2.sesiones import inicializar_sesiones
from src.vpn_rest_as.rutas import router as vpn_router
from src.vpn_rest_as.rf4 import router as rf4_rest_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    inicializar_sesiones(getattr(app.state, 'ruta_base_datos', None)) if getattr(app.state, 'ruta_base_datos', None) else inicializar_sesiones()
    yield


app = FastAPI(title='BYODSEC - RF2 / RF4 / VPN REST nativa', lifespan=lifespan)
app.include_router(rf2_router)
app.include_router(rf4_rest_router)
app.include_router(vpn_router)
