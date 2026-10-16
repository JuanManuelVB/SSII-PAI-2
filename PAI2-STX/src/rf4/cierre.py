"""Revocación persistente de tokens de sesión (RF4)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO, conectar_base_datos
from src.rf2.sesiones import _hash_token


def revocar_sesion(token: str, ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> bool:
    """Revoca solo el token presentado, nunca sesiones identificadas por otro usuario."""
    if not token:
        return False
    instante = datetime.now(timezone.utc).isoformat()
    with conectar_base_datos(ruta) as conexion:
        resultado = conexion.execute(
            """UPDATE sessions SET revoked_at=?
            WHERE token_hash=? AND revoked_at IS NULL AND expires_at > ?""",
            (instante, _hash_token(token), instante),
        )
    return resultado.rowcount == 1
