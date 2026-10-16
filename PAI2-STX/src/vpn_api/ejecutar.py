"""Arranque restringido a localhost del servicio REST en Ubuntu WSL2."""
from __future__ import annotations

import uvicorn
from src.vpn_api.seguridad import leer_token


def main() -> None:
    leer_token()
    uvicorn.run('src.vpn_api.app:app', host='127.0.0.1', port=8765,
                proxy_headers=False, access_log=False, log_level='info')


if __name__ == '__main__':
    main()
