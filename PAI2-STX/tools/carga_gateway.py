"""RS3: prueba de carga y concurrencia contra el gateway mTLS (RF2).

Lanza N sesiones completas RF2 simultáneas (challenge -> login firmado -> /me
-> logout) sobre TLS 1.3/mTLS, usando los certificados y contraseñas de los
usuarios RF5 precargados. Mide:

  * conexiones (ciclos) exitosas y con error,
  * latencia del login en ms (media, p50, p95, máx),
  * throughput (ciclos completos por segundo),
  * CPU y RAM del proceso del gateway durante la prueba (si se indica su PID).

NO establece túneles OpenVPN: mide la capa de autenticación del gateway, que es
la que decide cada acceso. El límite de 2 túneles simultáneos de Access Server
gratuito es una restricción de licencia, no del diseño; esta prueba demuestra
que la arquitectura de autenticación admite la concurrencia pedida (hasta 300).

Uso (desde la raíz del proyecto, con el gateway en marcha):
  python -m tools.carga_gateway --usuarios 50 --json bench/resultados/carga_50.json
  for N in 10 50 100 200 300; do python -m tools.carga_gateway --usuarios $N \
      --json bench/resultados/carga_$N.json; done
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import json
import os
import ssl
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

from src.rf2.autenticacion import mensaje_a_firmar

RAIZ = Path(__file__).resolve().parents[1]
DIR_RF5 = RAIZ / "pki" / "clients" / "rf5"
CA = RAIZ / "pki" / "ca" / "ca.crt"
CREDENCIALES = DIR_RF5 / "credenciales.csv"


def _contexto(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(CA))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def _firmar(clave, mensaje: bytes) -> str:
    if isinstance(clave, rsa.RSAPrivateKey):
        firma = clave.sign(mensaje, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(clave, ec.EllipticCurvePrivateKey):
        firma = clave.sign(mensaje, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("Tipo de clave no admitido")
    return base64.b64encode(firma).decode("ascii")


def cargar_identidades() -> list[dict]:
    """Empareja cada usuario RF5 con su certificado, clave y contraseña."""
    passwords: dict[str, str] = {}
    if CREDENCIALES.exists():
        with CREDENCIALES.open(encoding="utf-8", newline="") as f:
            for fila in csv.DictReader(f):
                passwords[fila["username"]] = fila["password"]
    identidades = []
    for crt in sorted(DIR_RF5.glob("*.crt")):
        usuario = crt.stem
        key = crt.with_suffix(".key")
        if not key.is_file() or usuario not in passwords:
            continue
        # device_id según el patrón de RF5: rf5_inv_001 -> rf5-inv-001-dev01.
        device_id = usuario.replace("_", "-") + "-dev01"
        identidades.append({"usuario": usuario, "device_id": device_id,
                            "cert": crt, "key": key, "password": passwords[usuario]})
    return identidades


async def _ciclo(url: str, ident: dict, metrica: dict) -> None:
    """Un ciclo RF2 completo; acumula resultado y latencia de login."""
    ctx = _contexto(ident["cert"], ident["key"])
    clave = serialization.load_pem_private_key(ident["key"].read_bytes(), password=None)
    cert_pem = ident["cert"].read_text(encoding="ascii")
    try:
        async with httpx.AsyncClient(verify=ctx, base_url=url, timeout=30.0) as cli:
            des = await cli.post("/api/v1/sessions/challenge",
                                 json={"username": ident["usuario"], "device_id": ident["device_id"]})
            if des.status_code != 200:
                metrica["errores"] += 1
                return
            nonce = des.json()["nonce"]
            firma = _firmar(clave, mensaje_a_firmar(nonce, ident["usuario"], ident["device_id"]))
            t0 = time.perf_counter()
            log = await cli.post("/api/v1/sessions/login", json={
                "username": ident["usuario"], "device_id": ident["device_id"],
                "password": ident["password"], "nonce": nonce,
                "certificate": cert_pem, "signature": firma})
            metrica["latencias_ms"].append((time.perf_counter() - t0) * 1000)
            if log.status_code != 200:
                metrica["errores"] += 1
                return
            token = log.json()["access_token"]
            cab = {"Authorization": f"Bearer {token}"}
            me = await cli.get("/api/v1/sessions/me", headers=cab)
            out = await cli.post("/api/v1/sessions/logout", headers=cab)
            if me.status_code == 200 and out.status_code == 200:
                metrica["exitosas"] += 1
            else:
                metrica["errores"] += 1
    except (httpx.HTTPError, ssl.SSLError, OSError, ValueError):
        metrica["errores"] += 1


def _muestra_proc(pid: int) -> tuple[int, int]:
    """(ticks_cpu, VmRSS_kB) de /proc/<pid> en Linux/WSL; (0,0) si no se puede."""
    try:
        campos = (Path(f"/proc/{pid}/stat").read_text().split())
        ticks = int(campos[13]) + int(campos[14])  # utime + stime
        rss = 0
        for linea in Path(f"/proc/{pid}/status").read_text().splitlines():
            if linea.startswith("VmRSS:"):
                rss = int(linea.split()[1])
                break
        return ticks, rss
    except (OSError, ValueError, IndexError):
        return 0, 0


async def ejecutar(url: str, usuarios: int, pid: int | None) -> dict:
    identidades = cargar_identidades()
    if not identidades:
        raise SystemExit("No hay identidades RF5. Ejecuta antes la precarga y la emisión de certificados.")
    seleccion = [identidades[i % len(identidades)] for i in range(usuarios)]
    metrica = {"exitosas": 0, "errores": 0, "latencias_ms": []}

    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    cpu0 = _muestra_proc(pid)[0] if pid else 0
    rss_pico = 0
    t_ini = time.perf_counter()
    tareas = [asyncio.create_task(_ciclo(url, ident, metrica)) for ident in seleccion]
    if pid:
        while not all(t.done() for t in tareas):
            rss_pico = max(rss_pico, _muestra_proc(pid)[1])
            await asyncio.sleep(0.2)
    await asyncio.gather(*tareas)
    duracion = time.perf_counter() - t_ini
    cpu_ticks = (_muestra_proc(pid)[0] - cpu0) if pid else 0

    lat = sorted(metrica["latencias_ms"])
    def pct(p: float) -> float:
        return round(lat[min(len(lat) - 1, int(p * len(lat)))], 1) if lat else 0.0
    documento = {
        "fecha_utc": datetime.now(timezone.utc).isoformat(),
        "usuarios_concurrentes": usuarios,
        "identidades_distintas": len(identidades),
        "conexiones_exitosas": metrica["exitosas"],
        "conexiones_con_error": metrica["errores"],
        "duracion_total_s": round(duracion, 3),
        "throughput_ciclos_por_s": round(metrica["exitosas"] / duracion, 2) if duracion else 0,
        "latencia_login_ms": {
            "media": round(statistics.fmean(lat), 1) if lat else 0.0,
            "p50": pct(0.50), "p95": pct(0.95), "max": round(max(lat), 1) if lat else 0.0,
        },
    }
    if pid:
        documento["gateway_cpu_s"] = round(cpu_ticks / hz, 3)
        documento["gateway_cpu_pct_medio"] = round(100 * (cpu_ticks / hz) / duracion, 1) if duracion else 0
        documento["gateway_ram_pico_mb"] = round(rss_pico / 1024, 1)
    return documento


def main() -> int:
    ap = argparse.ArgumentParser(description="RS3: carga concurrente sobre el gateway mTLS")
    ap.add_argument("--usuarios", type=int, default=50, help="Sesiones RF2 simultáneas")
    ap.add_argument("--url", default="https://localhost:9443")
    ap.add_argument("--pid", type=int, help="PID del gateway para medir CPU/RAM (ver $STATE/gateway.pid)")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    doc = asyncio.run(ejecutar(args.url, args.usuarios, args.pid))
    salida = json.dumps(doc, indent=2, ensure_ascii=False)
    print(salida)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(salida + "\n", encoding="utf-8")
    return 0 if doc["conexiones_con_error"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
