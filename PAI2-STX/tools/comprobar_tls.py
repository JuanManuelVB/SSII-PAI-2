"""RS2: comprueba en los servicios EN MARCHA que solo se negocia TLS 1.3.

Para cada servicio intenta dos conexiones reales:
  * TLS 1.3 (con certificado cliente si el servicio exige mTLS) -> debe funcionar
    y se registra la versión y la cipher suite negociada (AEAD + PFS en 1.3);
  * TLS 1.2 como máximo -> el servidor debe rechazarla.

Uso: python -m tools.comprobar_tls --json evidencias/logs/tls_servicios.json
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
CA_BYODSEC = RAIZ / "pki" / "ca" / "ca.crt"
CERT_DEMO = RAIZ / "pki" / "clients" / "rf5" / "rf5_inv_001.crt"
CLAVE_DEMO = RAIZ / "pki" / "clients" / "rf5" / "rf5_inv_001.key"


def _contexto(ca: Path, version: ssl.TLSVersion, cert: Path | None, key: Path | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca))
    ctx.minimum_version = version
    ctx.maximum_version = version
    if cert and key:
        ctx.load_cert_chain(str(cert), str(key))
    return ctx


def _intentar(puerto: int, ctx: ssl.SSLContext) -> dict:
    try:
        with socket.create_connection(("127.0.0.1", puerto), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                version, cifrado = tls.version(), tls.cipher()[0]
                # En TLS 1.3 el rechazo del certificado cliente llega tras el
                # handshake: una petición mínima confirma que el canal es usable.
                tls.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                tls.recv(1)
        return {"conecta": True, "version": version, "cipher_suite": cifrado}
    except (ssl.SSLError, OSError) as exc:
        return {"conecta": False, "error": type(exc).__name__}


def comprobar(servicio: str, puerto: int, ca: Path, cert: Path | None = None,
              key: Path | None = None) -> dict:
    tls13 = _intentar(puerto, _contexto(ca, ssl.TLSVersion.TLSv1_3, cert, key))
    tls12 = _intentar(puerto, _contexto(ca, ssl.TLSVersion.TLSv1_2, cert, key))
    aprobado = tls13["conecta"] and tls13.get("version") == "TLSv1.3" and not tls12["conecta"]
    return {"servicio": servicio, "puerto": puerto, "tls1_3": tls13,
            "tls1_2_rechazado": not tls12["conecta"], "aprobado": aprobado}


def main() -> int:
    parser = argparse.ArgumentParser(description="RS2: solo TLS 1.3 en los servicios del laboratorio")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--sin-access-server", action="store_true")
    args = parser.parse_args()
    resultados = [
        comprobar("Gateway RF2/RF4/VPN (mTLS)", 9443, CA_BYODSEC, CERT_DEMO, CLAVE_DEMO),
        comprobar("Registro RF1 (TLS servidor)", 8444, CA_BYODSEC),
    ]
    ca_as = os.environ.get("BYODSEC_AS_CA_BUNDLE")
    if not args.sin_access_server and ca_as:
        resultados.append(comprobar("Access Server web/REST", 943, Path(ca_as)))
    documento = {"fecha_utc": datetime.now(timezone.utc).isoformat(), "resultados": resultados,
                 "aprobado": all(r["aprobado"] for r in resultados)}
    salida = json.dumps(documento, indent=2, ensure_ascii=False)
    print(salida)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(salida + "\n", encoding="utf-8")
    return 0 if documento["aprobado"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
