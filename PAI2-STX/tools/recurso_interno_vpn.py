"""API REST de laboratorio para comprobar accesibilidad del recurso interno.

Solo enlaza en una IPv4 YA asignada a la interfaz VPN del servidor. No
configura el firewall, las rutas ni la VPN y no sirve datos sensibles.

Uso: python -m tools.recurso_interno_vpn --host IP_DE_INTERFAZ_VPN --port 8080
"""
from __future__ import annotations

import argparse
import json
import subprocess

from fastapi import FastAPI
import uvicorn

app = FastAPI(title="BYODSEC — Recurso corporativo simulado")


@app.get("/api/v1/recurso-interno")
def recurso_interno() -> dict[str, str]:
    return {
        "estado": "disponible",
        "recurso": "BYODSEC - recurso corporativo de laboratorio",
        "nota": "La respuesta NO demuestra por sí sola que el tráfico haya pasado por la VPN; verificar ruta y captura de red.",
    }


def ips_ipv4_locales() -> set[str]:
    try:
        raw = subprocess.check_output(
            ["ip", "-j", "-4", "addr", "show"], text=True, stderr=subprocess.DEVNULL
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Este comprobador necesita el comando 'ip' en Ubuntu/WSL.") from exc
    return {
        info["local"]
        for interfaz in json.loads(raw)
        for info in interfaz.get("addr_info", [])
        if info.get("family") == "inet" and "local" in info
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="API REST interna de laboratorio BYODSEC")
    parser.add_argument("--host", required=True, help="IPv4 de la interfaz VPN de Ubuntu")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.host in {"0.0.0.0", "127.0.0.1"}:
        parser.error("Usa la IPv4 asignada a la interfaz VPN, no 0.0.0.0 ni localhost")
    if args.host not in ips_ipv4_locales():
        parser.error("La IP solicitada no está asignada a ninguna interfaz IPv4 local")
    print(f"API REST laboratorio escuchando en http://{args.host}:{args.port}/api/v1/recurso-interno")
    print("AVISO: para asegurar acceso exclusivo por VPN, verificar rutas y reglas de firewall.")
    uvicorn.run(app, host=args.host, port=args.port, access_log=True)


if __name__ == "__main__":
    main()
