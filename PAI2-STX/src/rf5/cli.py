"""CLI RF5 con SQLite compartida por RF1 y RF5."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .gestion import ErrorRF5, emitir_certificados, precargar_usuarios, resumen_usuarios


def main() -> int:
    """Ejecuta las operaciones RF5 desde la terminal."""
    parser = argparse.ArgumentParser(
        description="RF5: usuarios corporativos y certificados de prueba"
    )
    sub = parser.add_subparsers(dest="accion", required=True)

    carga = sub.add_parser("precargar", help="Crear cuentas de prueba")
    carga.add_argument("--total", type=int, default=300)
    carga.add_argument("--db", type=Path, help="SQLite alternativa para pruebas")
    carga.add_argument("--credenciales", type=Path, help="CSV alternativo para pruebas")

    emision = sub.add_parser("certificados", help="Emitir certificados cliente")
    emision.add_argument("--limite", type=int)
    emision.add_argument("--db", type=Path, help="SQLite alternativa para pruebas")
    emision.add_argument("--destino", type=Path, help="Directorio alternativo")

    resumen = sub.add_parser("resumen", help="Consultar estadísticas")
    resumen.add_argument("--db", type=Path, help="SQLite alternativa para pruebas")
    args = parser.parse_args()

    try:
        if args.accion == "precargar":
            opciones = {"total": args.total}
            if args.db:
                opciones["ruta_base_datos"] = args.db
            if args.credenciales:
                opciones["ruta_credenciales"] = args.credenciales
            resultado = precargar_usuarios(**opciones)
        elif args.accion == "certificados":
            opciones = {"limite": args.limite}
            if args.db:
                opciones["ruta_base_datos"] = args.db
            if args.destino:
                opciones["directorio_destino"] = args.destino
            resultado = emitir_certificados(**opciones)
        else:
            resultado = resumen_usuarios(args.db) if args.db else resumen_usuarios()
        print(json.dumps(resultado, indent=2, ensure_ascii=False))
        return 0
    except (ErrorRF5, OSError, ValueError) as exc:
        parser.exit(1, f"Error RF5: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
