"""Arrancar gateway REST con el mismo TLS1.3/mTLS que BYODSEC existente."""
import argparse
import ssl

import uvicorn
from src.gateway.protocolo_mtls import MTLSH11Protocol
from src.server.tls import crear_contexto_tls_servidor


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8443)
    a = parser.parse_args()
    config = uvicorn.Config('src.vpn_rest_as.app:app', host=a.host, port=a.port,
                            proxy_headers=False, access_log=False, http=MTLSH11Protocol)
    config.load()
    config.ssl = crear_contexto_tls_servidor()
    config.ssl.options |= ssl.OP_NO_TICKET
    uvicorn.Server(config).run()


if __name__ == '__main__':
    main()
