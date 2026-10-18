"""Genera por REST un perfil OpenVPN individual ``userlogin`` (nunca autologin).

Uso (con las variables BYODSEC_AS_* cargadas, p. ej. por laboratorio.sh):
    python -m tools.generar_perfil_vpn --usuario rf5_inv_001 --destino ruta/perfil.ovpn

El perfil contiene material privado: se escribe con permisos 600, no se
sobrescribe si ya existe y nunca se imprime por pantalla.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from src.vpn_rest_as.client import AccessServerClient, AccessServerError, ConfigAccessServer


def generar(destino: Path, usuario: str, device_id: str = "") -> None:
    if destino.exists() or destino.is_symlink():
        raise FileExistsError(f"{destino} ya existe; no se sobrescribe material privado")
    contenido = AccessServerClient(ConfigAccessServer.desde_entorno()).generar_perfil_usuario(
        usuario, device_id=device_id)
    destino.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as archivo:
        archivo.write(contenido)


def main() -> int:
    parser = argparse.ArgumentParser(description="Perfil .ovpn userlogin por API REST de Access Server")
    parser.add_argument("--usuario", default="rf5_inv_001")
    parser.add_argument("--device-id", default="")
    parser.add_argument("--destino", type=Path, required=True)
    args = parser.parse_args()
    try:
        generar(args.destino, args.usuario, args.device_id)
    except (AccessServerError, OSError, ValueError) as exc:
        parser.exit(1, f"No se pudo generar el perfil VPN: {type(exc).__name__}: {exc}\n")
    print(f"Perfil privado creado: {args.destino} (NO subir a Git; importar en OpenVPN Connect)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
