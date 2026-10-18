"""Alta defensiva RF5 -> Access Server vía API REST oficial (cuentas BLOQUEADAS).

Uso: python -m src.vpn_rest_as.provision --usuario rf5_inv_001          # vista previa
     python -m src.vpn_rest_as.provision --usuario rf5_inv_001 --apply  # alta real
     python -m src.vpn_rest_as.provision --limit 3 --apply               # primeros N RF5

Las cuentas se crean con deny=true y autologin=false: solo una sesión RF2
válida las habilita (POST /api/v1/vpn/authorize). No sincroniza contraseñas
ni almacena claves privadas.
"""
from __future__ import annotations

import argparse

from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.vpn_rest_as.client import AccessServerClient, AccessServerError, ConfigAccessServer


def seleccionar_usuarios(usuarios: list[str] | None, limite: int) -> list[str]:
    inicializar_base_datos()
    with conectar_base_datos() as conn:
        if usuarios:
            marcas = ",".join("?" * len(usuarios))
            filas = conn.execute(
                f"SELECT username FROM users WHERE origin='RF5' AND status='active' "
                f"AND username IN ({marcas}) ORDER BY username", usuarios).fetchall()
            encontrados = [r['username'] for r in filas]
            faltan = sorted(set(usuarios) - set(encontrados))
            if faltan:
                raise ValueError('No son usuarios RF5 activos: ' + ', '.join(faltan))
            return encontrados
        return [r['username'] for r in conn.execute(
            "SELECT username FROM users WHERE origin='RF5' AND status='active' ORDER BY username LIMIT ?",
            (limite,)).fetchall()]


def main():
    parser = argparse.ArgumentParser(description='Alta bloqueada de usuarios RF5 en Access Server')
    parser.add_argument('--usuario', action='append', help='usuario RF5 concreto (repetible)')
    parser.add_argument('--limit', type=int, default=3)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.limit < 1 or args.limit > 3000:
        parser.error('limit debe estar entre 1 y 3000')
    try:
        usuarios = seleccionar_usuarios(args.usuario, args.limit)
    except ValueError as exc:
        parser.error(str(exc))
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
    print('Provisionados con deny=true. Solo RF2 los habilita.')


if __name__ == '__main__':
    main()
