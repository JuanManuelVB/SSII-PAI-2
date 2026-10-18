"""Configuración común de la capa TLS del gateway."""

from __future__ import annotations

from pathlib import Path

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
DIRECTORIO_CA = RAIZ_PROYECTO / "pki" / "ca"
DIRECTORIO_SERVIDOR = RAIZ_PROYECTO / "pki" / "server"

# Material público y privado que utilizará el gateway.
RUTA_CERTIFICADO_CA = DIRECTORIO_CA / "ca.crt"
RUTA_CERTIFICADO_SERVIDOR = DIRECTORIO_SERVIDOR / "server.crt"
RUTA_CLAVE_SERVIDOR = DIRECTORIO_SERVIDOR / "server.key"
