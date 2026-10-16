"""API integrada para RF1 + RF2 + RF4; acceso público solo mediante mTLS."""

from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI

from src.common.base_datos import inicializar_base_datos
from src.rf2.sesiones import inicializar_sesiones
from src.rf2.rutas import router as rf2_router
from src.rf4.rutas import router as rf4_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ruta = getattr(_app.state, "ruta_base_datos", None)
    if ruta is None:
        inicializar_base_datos()
        inicializar_sesiones()
    else:
        inicializar_base_datos(ruta)
        inicializar_sesiones(ruta)
    yield


app = FastAPI(title="PAI2: RF1 + RF2 + RF4", version="0.2.0", lifespan=lifespan)
app.include_router(rf2_router)
app.include_router(rf4_router)
# El registro RF1 se sirve por separado: requiere TLS de servidor, pero
# NO puede exigir certificado cliente antes del emparejamiento.
