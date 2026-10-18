"""Arranque obligatorio TLS 1.3/mTLS del gateway BYODSEC (RF2/RF4/VPN).

Ejecutar: python -m src.gateway.ejecutar [--port 9443]
Con BYODSEC_VPN_REST=1 se activa la integración REST con Access Server.
Nunca exponer los endpoints de autenticación con un servidor HTTP normal.
"""

from __future__ import annotations

import argparse
import ssl

import uvicorn

from src.gateway.protocolo_mtls import MTLSH11Protocol
from src.server.tls import crear_contexto_tls_servidor


def main() -> None:
    parser = argparse.ArgumentParser(description="Gateway BYODSEC TLS1.3/mTLS")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    args = parser.parse_args()
    # Se carga uvicorn primero y después se sustituye su contexto SSL por el
    # contexto TLS1.3 + certificado cliente obligatorio.
    config = uvicorn.Config("src.gateway.app:app", host=args.host, port=args.port,
                            proxy_headers=False, access_log=False, http=MTLSH11Protocol)
    config.load()
    config.ssl = crear_contexto_tls_servidor()
    config.ssl.options |= ssl.OP_NO_TICKET  # No reanudar sesiones TLS con tickets.
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
