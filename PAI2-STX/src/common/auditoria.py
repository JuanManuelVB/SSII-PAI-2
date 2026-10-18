"""Registro de auditoría común en JSONL (RS4).

Un único punto para escribir eventos trazables de conexión, desconexión e
intentos de acceso no autorizados. Nunca se registran contraseñas, tokens,
claves ni desafíos: solo identidades, marca temporal, resultado y motivo.

Formato de cada línea (una por evento):
    timestamp  (UTC ISO-8601)
    event      (p. ej. login_succeeded, login_failed, vpn_authorized)
    outcome    (success | failure)
    username   (si se conoce; "-" si no)
    device_id  (si se conoce; "-" si no)
    reason     (motivo público del rechazo; opcional)
    source     (componente que emite el evento: RF2, VPN, RF4, RF1)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
RUTA_AUDITORIA_ACCESOS = RAIZ / "evidencias" / "logs" / "accesos-audit.jsonl"

# Campos que nunca deben aparecer en un registro, por si se pasan por error.
_CAMPOS_PROHIBIDOS = {"password", "token", "access_token", "signature",
                      "nonce", "private_key", "clave", "contrasena"}


def registrar_evento(
    event: str,
    *,
    outcome: str,
    username: str | None = None,
    device_id: str | None = None,
    reason: str | None = None,
    source: str = "-",
    ruta: Path = RUTA_AUDITORIA_ACCESOS,
    **extra: str,
) -> None:
    """Añade un evento al registro de auditoría de accesos.

    Descarta en silencio cualquier campo sensible para que un error de llamada
    nunca escriba un secreto en disco.
    """
    registro = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "outcome": outcome,
        "username": username or "-",
        "device_id": device_id or "-",
        "source": source,
    }
    if reason:
        registro["reason"] = reason
    for clave, valor in extra.items():
        if clave.lower() in _CAMPOS_PROHIBIDOS:
            continue
        registro[clave] = valor
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with ruta.open("a", encoding="utf-8") as archivo:
        archivo.write(json.dumps(registro, ensure_ascii=False, sort_keys=True) + "\n")
