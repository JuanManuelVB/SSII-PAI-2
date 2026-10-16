"""Precarga defensiva RF5 -> Access Server vía API REST oficial.

Uso: python -m src.vpn_rest_as.provision --limit 3  # vista previa
     python -m src.vpn_rest_as.provision --limit 3 --apply

No crea ni sincroniza contraseñas: Access Server requiere configuración
adicional de un método de autenticación. No almacena claves privadas.
"""
from __future__ import annotations
import argparse
from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer, AccessServerError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--limit', type=int, default=3)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.limit < 1 or args.limit > 3000:
        parser.error('limit debe estar entre 1 y 3000')
    inicializar_base_datos()
    with conectar_base_datos() as conn:
        usuarios = [r['username'] for r in conn.execute(
            "SELECT username FROM users WHERE origin='RF5' AND status='active' ORDER BY username LIMIT ?",
            (args.limit,)).fetchall()]
    if not usuarios:
        parser.error('No hay usuarios RF5 activos')
    print(f'Usuarios seleccionados: {len(usuarios)}')
    print('Ejemplos:', ', '.join(usuarios[:3]))
    if not args.apply:
        print('DRY-RUN: no se ha creado ninguna cuenta VPN')
        return
    api = AccessServerClient(ConfigAccessServer.desde_entorno())
    for usuario in usuarios:
        try:
            api.crear_usuario_bloqueado(usuario)
            print('Creado y bloqueado:', usuario)
        except AccessServerError as exc:
            print('ERROR (revisar en panel, sin sobrescribir):', usuario, str(exc))
            raise SystemExit(1) from exc
    print('Provisionados. Configure credenciales y perfiles propios en Access Server.')


if __name__ == '__main__':
    main()
