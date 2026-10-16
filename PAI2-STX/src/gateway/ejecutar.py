"""Arranque obligatorio TLS 1.3/mTLS para el gateway integrado.

Ejecutar: python -m src.gateway.ejecutar
No exponer los endpoints de autenticación con un servidor HTTP normal.
"""

from __future__ import annotations

import argparse
import ssl

import uvicorn
from src.server.tls import crear_contexto_tls_servidor
from src.gateway.protocolo_mtls import MTLSH11Protocol


def main() -> None:
    parser = argparse.ArgumentParser(description="Gateway PAI2 TLS1.3/mTLS")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    # Se carga uvicorn primero y después se sustituye su contexto SSL por el
    # de TLS1.3/mTLS, compartido con el módulo del compañero.
    config = uvicorn.Config("src.gateway.app:app", host=args.host, port=args.port,
                            proxy_headers=False, access_log=False, http=MTLSH11Protocol)
    config.load()
    config.ssl = crear_contexto_tls_servidor()
    config.ssl.options |= ssl.OP_NO_TICKET  # No reanudar sesiones TLS con tickets.
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
