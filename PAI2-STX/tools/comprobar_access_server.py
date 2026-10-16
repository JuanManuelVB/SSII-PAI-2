"""Diagnóstico seguro de la API REST: python -m tools.comprobar_access_server.
Nunca imprime tokens, contraseñas, nombres/IPs de otros clientes.
"""
from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer, AccessServerError


def main():
    try:
        cliente=AccessServerClient(ConfigAccessServer.desde_entorno())
        status=cliente.status()
        conexiones=status.get('vpn_clients',[])
        if not isinstance(conexiones,list):
            raise AccessServerError('Formato vpn_clients incorrecto')
        print('REST OK, numero de conexiones VPN:',len(conexiones))
    except AccessServerError as exc:
        raise SystemExit(f'ERROR REST: {exc}') from exc

if __name__=='__main__': main()
