"""RS4: reúne los registros de auditoría JSONL en un único CSV depurado.

El empaquetado de la entrega excluye los ``*.jsonl`` (pueden contener IPs); en
cambio incluye los ``*.csv``. Esta herramienta vuelca los eventos de RF1
(registro), RF2/VPN (accesos) y RF4 (cierres) en
``evidencias/logs/auditoria_accesos.csv``, con columnas uniformes y sin
contraseñas, tokens ni claves, listo para entregar.

Uso: python -m tools.exportar_auditoria_csv
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
LOGS = RAIZ / "evidencias" / "logs"
FUENTES = {
    "RF1": LOGS / "rf1-audit.jsonl",
    "RF2/VPN": LOGS / "accesos-audit.jsonl",
    "RF4": LOGS / "rf4-audit.jsonl",
}
SALIDA = LOGS / "auditoria_accesos.csv"
COLUMNAS = ["timestamp", "source", "event", "outcome", "username", "device_id", "reason"]
_SENSIBLES = {"password", "token", "access_token", "signature", "nonce"}


def _filas() -> list[dict]:
    filas: list[dict] = []
    for origen, ruta in FUENTES.items():
        if not ruta.exists():
            continue
        with ruta.open(encoding="utf-8", errors="replace") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    dato = json.loads(linea)
                except ValueError:
                    continue
                if any(c in dato for c in _SENSIBLES):
                    dato = {k: v for k, v in dato.items() if k not in _SENSIBLES}
                filas.append({
                    "timestamp": dato.get("timestamp", ""),
                    "source": dato.get("source", origen),
                    "event": dato.get("event", ""),
                    "outcome": dato.get("outcome", ""),
                    "username": dato.get("username", ""),
                    "device_id": dato.get("device_id", ""),
                    "reason": dato.get("reason", ""),
                })
    filas.sort(key=lambda d: d["timestamp"])
    return filas


def main() -> int:
    filas = _filas()
    LOGS.mkdir(parents=True, exist_ok=True)
    with SALIDA.open("w", encoding="utf-8", newline="") as f:
        escritor = csv.DictWriter(f, fieldnames=COLUMNAS)
        escritor.writeheader()
        escritor.writerows(filas)
    print(f"{len(filas)} eventos exportados a {SALIDA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
