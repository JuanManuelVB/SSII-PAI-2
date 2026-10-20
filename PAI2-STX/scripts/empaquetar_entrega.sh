#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 scripts/crear_zip_limpio.py "${1:-../PAI2-STX_CAMINO_A_LIMPIO.zip}"
