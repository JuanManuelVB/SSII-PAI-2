"""Consola independiente del RF5: python -m src.rf5.cli ..."""

from __future__ import annotations

import argparse
import json

from .gestion import ErrorRF5, emitir_certificados, precargar_usuarios, resumen_usuarios


def main() -> int:
    parser = argparse.ArgumentParser(description="RF5: usuarios corporativos y certificados de prueba")
    sub = parser.add_subparsers(dest="accion", required=True)
    carga = sub.add_parser("precargar", help="Crear/recuperar hasta 300 cuentas de prueba")
    carga.add_argument("--total", type=int, default=300, help="Número total de usuarios RF5 (por defecto 300)")
    emision = sub.add_parser("certificados", help="Emitir certificados con la CA ya existente")
    emision.add_argument("--limite", type=int, help="Emitir solo N usuarios, útil en pruebas")
    sub.add_parser("resumen", help="Consultar estadísticas sin mostrar contraseñas")
    args = parser.parse_args()
    try:
        if args.accion == "precargar":
            resultado = precargar_usuarios(total=args.total)
        elif args.accion == "certificados":
            resultado = emitir_certificados(limite=args.limite)
        else:
            resultado = resumen_usuarios()
        print(json.dumps(resultado, indent=2, ensure_ascii=False))
        return 0
    except (ErrorRF5, OSError, PermissionError) as exc:
        parser.exit(1, f"Error RF5: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
