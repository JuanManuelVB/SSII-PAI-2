"""Registro RF1 por HTTPS/TLS 1.3 sin certificado cliente previo.

Separa el alta de nuevos dispositivos de la entrada mTLS protegida.
Ejecutar: python -m src.gateway.ejecutar_registro
"""

from __future__ import annotations

import argparse
import ssl

import uvicorn
from src.common.config_tls import RUTA_CERTIFICADO_SERVIDOR, RUTA_CLAVE_SERVIDOR


def main() -> None:
    parser = argparse.ArgumentParser(description="Registro inicial RF1 sobre TLS 1.3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8444)
    args = parser.parse_args()
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_3
    contexto.maximum_version = ssl.TLSVersion.TLSv1_3
    contexto.load_cert_chain(str(RUTA_CERTIFICADO_SERVIDOR), str(RUTA_CLAVE_SERVIDOR))
    contexto.verify_mode = ssl.CERT_NONE
    config = uvicorn.Config("src.server.app:app", host=args.host, port=args.port,
                            proxy_headers=False, access_log=False)
    config.load()
    config.ssl = contexto
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
