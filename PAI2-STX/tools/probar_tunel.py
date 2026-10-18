"""Prueba en Windows de acceso exclusivamente vía VPN (un paso cada vez).

Ejemplos:
  py -m tools.probar_tunel --fase sin-vpn --ip 172.27.224.1
  py -m tools.probar_tunel --fase con-vpn --ip 172.27.224.1
  py -m tools.probar_tunel --fase tras-logout --ip 172.27.224.1
"""
from __future__ import annotations
import argparse
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
import httpx


def comprobar(ip: str, port: int = 8080, timeout: float = 3.0) -> dict:
    destino = ipaddress.ip_address(ip)
    if destino.version != 4 or not destino.is_private or destino.is_loopback:
        raise ValueError('Usa una IPv4 privada de la interfaz Access Server, no localhost')
    try:
        with httpx.Client(trust_env=False, timeout=timeout, follow_redirects=False) as client:
            response = client.get(f'http://{ip}:{port}/api/v1/recurso-interno')
        alcanza = (response.status_code == 200 and
                   response.json().get('estado') == 'disponible')
    except (httpx.RequestError, ValueError):
        alcanza = False
    return {'recurso_alcanzable': alcanza, 'ip_recurso': ip, 'puerto': port}


def main() -> int:
    ap=argparse.ArgumentParser(description='Comprobar acceso al recurso interno antes, durante y después de VPN')
    ap.add_argument('--fase', choices=('sin-vpn','con-vpn','tras-logout'), required=True)
    ap.add_argument('--ip', required=True)
    ap.add_argument('--puerto', type=int, default=8080)
    ap.add_argument('--salida', type=Path, default=Path('evidencias/logs/acceso_vpn.jsonl'))
    args=ap.parse_args()
    resultado=comprobar(args.ip,args.puerto)
    esperado = args.fase == 'con-vpn'
    salida={'fecha_utc':datetime.now(timezone.utc).isoformat(), 'fase': args.fase,
            'esperado_alcanzable': esperado, **resultado,
            'resultado': 'PASS' if resultado['recurso_alcanzable']==esperado else 'FAIL'}
    args.salida.parent.mkdir(parents=True,exist_ok=True)
    with args.salida.open('a',encoding='utf-8') as f:
        f.write(json.dumps(salida,ensure_ascii=False)+'\n')
    print(json.dumps(salida, indent=2, ensure_ascii=False))
    return 0 if salida['resultado']=='PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
