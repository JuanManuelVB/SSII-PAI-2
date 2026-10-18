"""RS3/RS8: mide rendimiento desde el cliente contra el MISMO recurso, con y
sin VPN, para comparar tráfico cifrado frente a tráfico directo sin cifrar.

Lanza iperf3 contra un servidor iperf3 (`iperf3 -s` en el destino) y mide el
RTT con ping. Guarda un JSON normalizado por ejecución en bench/resultados/,
que luego dibuja `tools.graficas_rendimiento`.

Cómo comparar correctamente (lo exige el enunciado):
  * «directa»: contra la IP del destino SIN la VPN conectada (tráfico en claro).
  * «vpn»    : contra la MISMA IP con el túnel conectado (tráfico cifrado).
  Mantener idéntico destino, duración y nº de flujos en ambas medidas.

Funciona en Windows (py -m tools.medir_cliente) y en Linux/WSL.

Uso:
  py -m tools.medir_cliente --etiqueta directa --host 192.168.1.50
  py -m tools.medir_cliente --etiqueta vpn     --host 192.168.1.50
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
DESTINO = RAIZ / "bench" / "resultados"


def _iperf3(host: str, segundos: int, flujos: int) -> dict:
    binario = shutil.which("iperf3")
    if not binario:
        raise SystemExit("Falta iperf3. Instálalo en el cliente y en el destino (iperf3 -s).")
    proc = subprocess.run([binario, "-c", host, "-t", str(segundos), "-P", str(flujos), "-J"],
                          capture_output=True, text=True, timeout=segundos + 30)
    if proc.returncode != 0:
        raise SystemExit(f"iperf3 falló: {proc.stderr.strip() or proc.stdout.strip()}")
    datos = json.loads(proc.stdout)
    recibido = datos["end"]["sum_received"]["bits_per_second"]
    enviado = datos["end"]["sum_sent"]["bits_per_second"]
    return {"throughput_mbps": round(recibido / 1e6, 2),
            "throughput_envio_mbps": round(enviado / 1e6, 2),
            "iperf3_json": datos}


def _ping_rtt(host: str, paquetes: int = 20) -> float | None:
    binario = shutil.which("ping")
    if not binario:
        return None
    windows = platform.system() == "Windows"
    orden = [binario, "-n" if windows else "-c", str(paquetes), host]
    try:
        proc = subprocess.run(orden, capture_output=True, text=True, timeout=paquetes + 30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    texto = proc.stdout
    # Linux/WSL: rtt min/avg/max/mdev = 0.1/0.4/1.2/0.3 ms
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", texto)
    if m:
        return round(float(m.group(1)), 3)
    # Windows (inglés): Average = 12ms ; (español): Media = 12ms
    m = re.search(r"(?:Average|Media)\s*=\s*(\d+)\s*ms", texto)
    if m:
        return float(m.group(1))
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Medición de rendimiento cliente (iperf3 + ping)")
    ap.add_argument("--etiqueta", required=True, choices=("directa", "vpn"))
    ap.add_argument("--host", required=True, help="IP del destino (servidor iperf3)")
    ap.add_argument("--segundos", type=int, default=20)
    ap.add_argument("--flujos", type=int, default=4)
    ap.add_argument("--paquetes-ping", type=int, default=20)
    args = ap.parse_args()

    medida = _iperf3(args.host, args.segundos, args.flujos)
    rtt = _ping_rtt(args.host, args.paquetes_ping)
    documento = {
        "fecha_utc": datetime.now(timezone.utc).isoformat(),
        "etiqueta": args.etiqueta,
        "host": args.host,
        "segundos": args.segundos,
        "flujos": args.flujos,
        "throughput_mbps": medida["throughput_mbps"],
        "throughput_envio_mbps": medida["throughput_envio_mbps"],
        "rtt_ms_medio": rtt,
    }
    DESTINO.mkdir(parents=True, exist_ok=True)
    marca = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ruta = DESTINO / f"{args.etiqueta}_{marca}.json"
    # Guarda también el JSON crudo de iperf3 aparte, por si se quiere revisar.
    ruta.write_text(json.dumps(documento, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (DESTINO / f"{args.etiqueta}_{marca}_iperf3.json").write_text(
        json.dumps(medida["iperf3_json"], indent=2) + "\n", encoding="utf-8")
    print(json.dumps(documento, indent=2, ensure_ascii=False))
    print(f"\nGuardado en {ruta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
