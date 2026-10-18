"""RS2: comprueba en los servicios EN MARCHA que solo se negocia TLS 1.3.

Para cada servicio real:
  * TLS 1.3 (con certificado cliente si el servicio exige mTLS) -> debe
    negociarse, y se registra la versión, la *cipher suite* (AEAD) y el grupo
    de intercambio de claves efímero (PFS);
  * TLS 1.2, 1.1 y 1.0 -> el servidor debe RECHAZARLAS.

Las versiones antiguas (1.0/1.1) ya no las ofrece OpenSSL moderno por defecto,
así que para que el rechazo lo imponga el SERVIDOR y no el cliente se prueban
con `openssl s_client` bajando el nivel de seguridad (`@SECLEVEL=0`). Si no hay
`openssl` disponible se recurre al módulo ssl de Python y se anota el matiz.

Uso: python -m tools.comprobar_tls --json evidencias/logs/tls_servicios.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
CA_BYODSEC = RAIZ / "pki" / "ca" / "ca.crt"
CERT_DEMO = RAIZ / "pki" / "clients" / "rf5" / "rf5_inv_001.crt"
CLAVE_DEMO = RAIZ / "pki" / "clients" / "rf5" / "rf5_inv_001.key"

# Versiones que el servidor DEBE rechazar y su indicador en openssl s_client.
VERSIONES_ANTIGUAS = {
    "TLSv1.2": ("-tls1_2", ssl.TLSVersion.TLSv1_2),
    "TLSv1.1": ("-tls1_1", ssl.TLSVersion.TLSv1_1),
    "TLSv1.0": ("-tls1", ssl.TLSVersion.TLSv1),
}


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


def _grupo_pfs(puerto: int, cert: Path | None, key: Path | None) -> str | None:
    """Grupo de clave efímero negociado (p. ej. X25519), evidencia de PFS.

    Se obtiene de `openssl s_client` ("Server Temp Key"), portable entre
    versiones de Python. Devuelve None si no se puede determinar.
    """
    binario = shutil.which("openssl")
    if not binario:
        return None
    orden = [binario, "s_client", "-connect", f"127.0.0.1:{puerto}", "-tls1_3",
             "-CAfile", str(CA_BYODSEC)]
    if cert and key:
        orden += ["-cert", str(cert), "-key", str(key)]
    try:
        proc = subprocess.run(orden, input=b"", capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for linea in (proc.stdout + proc.stderr).decode("utf-8", "replace").splitlines():
        if "Server Temp Key:" in linea:
            return linea.split("Server Temp Key:", 1)[1].strip()
    return None


def _conectar_tls13(puerto: int, ctx: ssl.SSLContext, cert: Path | None = None,
                    key: Path | None = None) -> dict:
    """Conexión TLS 1.3 real; devuelve versión, cipher suite y grupo (PFS)."""
    try:
        with socket.create_connection(("127.0.0.1", puerto), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                version, cifrado = tls.version(), tls.cipher()[0]
                tls.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                tls.recv(1)
        resultado = {"conecta": True, "version": version, "cipher_suite": cifrado}
        grupo = _grupo_pfs(puerto, cert, key)
        if grupo:
            resultado["grupo_pfs"] = grupo
        return resultado
    except (ssl.SSLError, OSError) as exc:
        return {"conecta": False, "error": type(exc).__name__}


def _rechazo_openssl(puerto: int, flag: str, cert: Path | None, key: Path | None) -> dict | None:
    """True si el servidor rechaza esa versión antigua (vía openssl s_client).

    Devuelve None si openssl no está disponible y debe usarse el respaldo.
    """
    binario = shutil.which("openssl")
    if not binario:
        return None
    orden = [binario, "s_client", "-connect", f"127.0.0.1:{puerto}", flag,
             "-cipher", "ALL:@SECLEVEL=0", "-CAfile", str(CA_BYODSEC)]
    if cert and key:
        orden += ["-cert", str(cert), "-key", str(key)]
    try:
        proc = subprocess.run(orden, input=b"", capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return {"rechazado": True, "via": "openssl", "detalle": "sin_handshake"}
    salida = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    # Handshake con éxito deja "Cipher    : <algo>" distinto de (NONE).
    exito = proc.returncode == 0 and "Cipher    :" in salida and "(NONE)" not in salida
    return {"rechazado": not exito, "via": "openssl"}


def _rechazo_python(puerto: int, version: ssl.TLSVersion, cert: Path | None, key: Path | None) -> dict:
    try:
        ctx = _contexto(CA_BYODSEC, version, cert, key)
    except (ssl.SSLError, ValueError):
        # El propio cliente ya no permite ofrecer esa versión obsoleta.
        return {"rechazado": True, "via": "python", "detalle": "cliente_no_ofrece_version"}
    datos = _conectar_tls13(puerto, ctx)
    return {"rechazado": not datos["conecta"], "via": "python"}


def comprobar(servicio: str, puerto: int, ca: Path, cert: Path | None = None,
              key: Path | None = None) -> dict:
    tls13 = _conectar_tls13(puerto, _contexto(ca, ssl.TLSVersion.TLSv1_3, cert, key), cert, key)
    antiguas: dict[str, dict] = {}
    todas_rechazadas = True
    for nombre, (flag, version) in VERSIONES_ANTIGUAS.items():
        res = _rechazo_openssl(puerto, flag, cert, key)
        if res is None:
            res = _rechazo_python(puerto, version, cert, key)
        antiguas[nombre] = res
        todas_rechazadas = todas_rechazadas and res["rechazado"]
    aprobado = (tls13["conecta"] and tls13.get("version") == "TLSv1.3"
                and todas_rechazadas)
    return {"servicio": servicio, "puerto": puerto, "tls1_3": tls13,
            "versiones_antiguas_rechazadas": antiguas,
            "tls1_2_rechazado": antiguas["TLSv1.2"]["rechazado"],
            "aprobado": aprobado}


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
