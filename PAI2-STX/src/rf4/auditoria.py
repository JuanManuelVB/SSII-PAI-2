"""Registro de eventos de RF4 en JSONL, sin credenciales ni tokens."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
RUTA_AUDITORIA = RAIZ / "evidencias" / "logs" / "rf4-audit.jsonl"


def registrar_cierre(username: str, device_id: str, *, ruta: Path = RUTA_AUDITORIA) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    registro = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "session_closed",
        "username": username,
        "device_id": device_id,
    }
    with ruta.open("a", encoding="utf-8") as salida:
        salida.write(json.dumps(registro, ensure_ascii=False, sort_keys=True) + "\n")
