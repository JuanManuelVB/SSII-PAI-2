"""CLI RF5 con base de datos SQLite compartida por RF1 y RF5.

El comando migrar es el único que lee el JSON anterior. Los demás comandos
operan sobre SQLite y no regeneran el antiguo JSON.
"""

import argparse
import json

from .gestion import ErrorRF5
from .sqlite_store import (asociar_certificados, importar_json, precargar_sqlite,
                           resumen_sqlite)


def main() -> int:
    parser = argparse.ArgumentParser(description='RF5 integrado con SQLite de RF1')
    subs = parser.add_subparsers(dest='accion', required=True)
    subs.add_parser('migrar', help='Importar el JSON antiguo una vez sin sobrescribir usuarios RF1')
    p = subs.add_parser('precargar', help='Crear usuarios adicionales directamente en SQLite')
    p.add_argument('--total', type=int, default=300)
    p = subs.add_parser('certificados', help='Emitir/reutilizar certificados con la CA y vincularlos')
    p.add_argument('--limite', type=int)
    subs.add_parser('resumen', help='Consultar el estado de la base SQLite')
    args = parser.parse_args()
    try:
        if args.accion == 'migrar':
            salida = importar_json()
        elif args.accion == 'precargar':
            salida = precargar_sqlite(total=args.total)
        elif args.accion == 'certificados':
            salida = asociar_certificados(limite=args.limite)
        else:
            salida = resumen_sqlite()
        print(json.dumps(salida, indent=2, ensure_ascii=False))
        return 0
    except (ErrorRF5, OSError, ValueError) as exc:
        parser.exit(1, f'Error RF5/SQLite: {exc}\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
