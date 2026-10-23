"""Línea base HTTP de RS3, exclusivamente en 127.0.0.1 (sin datos reales).

La implementación devuelve el mismo digest SHA-256 y longitud que
`/api/v1/resources/echo`, pero SIN TLS y SIN control de acceso.
No usar contraseñas, tokens ni datos personales como carga de prueba.
"""
from __future__ import annotations

import argparse
import hashlib
from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="BYODSEC RS3 - línea base HTTP local")


class Mensaje(BaseModel):
    mensaje: str = Field(min_length=1, max_length=2048)


@app.get("/health")
def health() -> dict[str, str]:
    return {"servicio": "byodsec_rs3_http_sin_cifrar", "estado": "ok"}


@app.post("/echo")
def echo(datos: Mensaje) -> dict[str, str | int]:
    contenido = datos.mensaje.encode("utf-8")
    return {"status": "processed", "bytes": len(contenido),
            "sha256": hashlib.sha256(contenido).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP de comparación RS3 solo en loopback")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9080)
    args = parser.parse_args()
    if args.host != "127.0.0.1":
        parser.error("Por seguridad, la línea base HTTP solo admite 127.0.0.1")
    if not (1024 <= args.port <= 65535):
        parser.error("Puerto fuera de rango")
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
