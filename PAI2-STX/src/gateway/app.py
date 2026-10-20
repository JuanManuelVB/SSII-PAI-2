"""Gateway REST corporativo BYODSEC protegido mediante TLS 1.3/mTLS.

El registro de dispositivos se expone por separado en 8444, porque los
clientes nuevos aún no disponen de certificado propio.
"""
from __future__ import annotations
from contextlib import asynccontextmanager
from fastapi import FastAPI
from src.common.base_datos import inicializar_base_datos
from src.rf2.rutas import router as rf2_router
from src.rf4.rutas import router as rf4_router
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

def crear_app(vpn_rest: bool = False) -> FastAPI:
    """Crea el gateway del camino A; conserva vpn_rest=False por compatibilidad."""
    if vpn_rest:
        raise ValueError("Modo OpenVPN retirado: despliegue del camino A HTTPS/mTLS")
    aplicacion = FastAPI(title="BYODSEC · Camino A · HTTPS/TLS 1.3/mTLS",
                        version="1.0.0", lifespan=lifespan)
    aplicacion.include_router(rf2_router)
    aplicacion.include_router(rf4_router)
    aplicacion.include_router(recursos_router)
    return aplicacion

app = crear_app()
