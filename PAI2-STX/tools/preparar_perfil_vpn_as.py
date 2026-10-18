"""Emite y almacena un perfil userlogin por REST, privado y sin imprimirlo.

Es una preparación administrativa LOCAL, no una autenticación por RF2.
La identidad VPN de Access Server requiere credenciales propias y debe
ser vinculada al dispositivo antes de declarar completado RS1 en el túnel.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer


def main() -> int:
    ap = argparse.ArgumentParser(description='Crear perfil .ovpn individual userlogin sin mostrar claves')
    ap.add_argument('username')
    ap.add_argument('--device-id', default='')
    ap.add_argument('--destino', type=Path)
    args = ap.parse_args()
    destino = args.destino or Path('pki/clients/rf5') / f'{args.username}.ovpn'
    if destino.exists() or destino.is_symlink():
        ap.error('El perfil ya existe; no se sobrescribe material privado')
    contenido = AccessServerClient(ConfigAccessServer.desde_entorno()).generar_perfil_usuario(
        args.username, device_id=args.device_id)
    destino.parent.mkdir(parents=True, exist_ok=True)
    fd=os.open(destino, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(contenido)
    print(f'Perfil privado creado: {destino}. NO SUBIR A GITHUB. Importar en OpenVPN Connect.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
