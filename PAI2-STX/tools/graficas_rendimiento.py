"""RS3/RS8: dibuja las gráficas de rendimiento a partir de bench/resultados/.

Lee dos tipos de ficheros JSON y genera PNG en bench/resultados/:

  1. carga_<N>.json  (de tools.carga_gateway): escalabilidad del gateway.
     -> grafica_escalabilidad.png: throughput y latencia p95 frente al nº de
        sesiones concurrentes (10, 50, 100, 200, 300).

  2. directa_*.json / vpn_*.json  (de tools.medir_cliente): comparación con y
     sin VPN sobre el mismo recurso.
     -> grafica_overhead_vpn.png: throughput (Mbps) y RTT (ms), directa vs VPN,
        con el overhead en %.

Uso: python -m tools.graficas_rendimiento
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # sin entorno gráfico
import matplotlib.pyplot as plt

RAIZ = Path(__file__).resolve().parents[1]
DIR = RAIZ / "bench" / "resultados"

# Paleta sobria y legible, coherente entre las dos gráficas.
AZUL = "#2563eb"
NARANJA = "#ea7317"
GRIS = "#64748b"


def _cargar(patron: str) -> list[dict]:
    datos = []
    for ruta in sorted(DIR.glob(patron)):
        try:
            datos.append(json.loads(ruta.read_text(encoding="utf-8")))
        except (ValueError, OSError):
            continue
    return datos


def grafica_escalabilidad() -> Path | None:
    registros = _cargar("carga_*.json")
    if not registros:
        return None
    registros.sort(key=lambda d: d.get("usuarios_concurrentes", 0))
    x = [d["usuarios_concurrentes"] for d in registros]
    throughput = [d.get("throughput_ciclos_por_s", 0) for d in registros]
    p95 = [d.get("latencia_login_ms", {}).get("p95", 0) for d in registros]

    fig, ax1 = plt.subplots(figsize=(8, 5))
    ax1.set_title("Escalabilidad del gateway mTLS (RF2) — RS3", fontsize=13, weight="bold")
    ax1.set_xlabel("Sesiones concurrentes")
    ax1.set_ylabel("Throughput (ciclos login/s)", color=AZUL)
    ax1.plot(x, throughput, "o-", color=AZUL, label="Throughput")
    ax1.tick_params(axis="y", labelcolor=AZUL)
    ax1.grid(True, alpha=0.3)

    ax2 = ax1.twinx()
    ax2.set_ylabel("Latencia login p95 (ms)", color=NARANJA)
    ax2.plot(x, p95, "s--", color=NARANJA, label="Latencia p95")
    ax2.tick_params(axis="y", labelcolor=NARANJA)

    fig.tight_layout()
    salida = DIR / "grafica_escalabilidad.png"
    fig.savefig(salida, dpi=130)
    plt.close(fig)
    return salida


def _media(registros: list[dict], campo: str) -> float | None:
    valores = [d[campo] for d in registros if isinstance(d.get(campo), (int, float))]
    return round(sum(valores) / len(valores), 2) if valores else None


def grafica_overhead() -> Path | None:
    directa = _cargar("directa_*.json")
    vpn = _cargar("vpn_*.json")
    # No mezclar con los ficheros crudos *_iperf3.json (no tienen 'etiqueta').
    directa = [d for d in directa if d.get("etiqueta") == "directa"]
    vpn = [d for d in vpn if d.get("etiqueta") == "vpn"]
    if not directa or not vpn:
        return None

    tp_dir = _media(directa, "throughput_mbps") or 0
    tp_vpn = _media(vpn, "throughput_mbps") or 0
    rtt_dir = _media(directa, "rtt_ms_medio") or 0
    rtt_vpn = _media(vpn, "rtt_ms_medio") or 0
    ov_tp = round(100 * (tp_dir - tp_vpn) / tp_dir, 1) if tp_dir else 0
    ov_rtt = round(100 * (rtt_vpn - rtt_dir) / rtt_dir, 1) if rtt_dir else 0

    fig, (axa, axb) = plt.subplots(1, 2, figsize=(10, 5))
    fig.suptitle("Rendimiento con y sin VPN sobre el mismo recurso — RS3",
                 fontsize=13, weight="bold")

    axa.bar(["Directa", "VPN"], [tp_dir, tp_vpn], color=[GRIS, AZUL])
    axa.set_ylabel("Throughput (Mbps)")
    axa.set_title(f"Throughput · overhead {ov_tp}%")
    for i, v in enumerate([tp_dir, tp_vpn]):
        axa.text(i, v, f"{v}", ha="center", va="bottom")

    axb.bar(["Directa", "VPN"], [rtt_dir, rtt_vpn], color=[GRIS, NARANJA])
    axb.set_ylabel("RTT medio (ms)")
    axb.set_title(f"Latencia · overhead {ov_rtt}%")
    for i, v in enumerate([rtt_dir, rtt_vpn]):
        axb.text(i, v, f"{v}", ha="center", va="bottom")

    fig.tight_layout(rect=(0, 0, 1, 0.95))
    salida = DIR / "grafica_overhead_vpn.png"
    fig.savefig(salida, dpi=130)
    plt.close(fig)
    return salida


def main() -> int:
    generadas = [g for g in (grafica_escalabilidad(), grafica_overhead()) if g]
    if not generadas:
        print("No hay datos en bench/resultados/. Ejecuta antes carga_gateway y/o medir_cliente.")
        return 1
    for ruta in generadas:
        print(f"Generada: {ruta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
