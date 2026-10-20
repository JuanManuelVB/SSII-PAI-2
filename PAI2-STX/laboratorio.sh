#!/usr/bin/env bash
# Entrada sencilla del camino A (sin OpenVPN ni máquinas virtuales).
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-ayuda}" in
  preparar) bash scripts/preparar_camino_a.sh ;;
  servidor|iniciar) bash scripts/iniciar_servidor_camino_a.sh ;;
  auditar) .venv-wsl/bin/python -m tools.auditar_rf1_rf5_pki --total 300 ;;
  prueba300) .venv-wsl/bin/python -m tools.carga_300_sesiones --usuarios 300 --duracion 120 --preparacion 600 --concurrencia-auth 6 --reintentos-http-500 2 --json bench/resultados/sesiones_300.json ;;
  *) echo 'Uso: bash laboratorio.sh preparar|servidor|auditar|prueba300';;
esac
