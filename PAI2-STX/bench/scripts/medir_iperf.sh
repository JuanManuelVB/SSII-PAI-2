#!/usr/bin/env bash
set -euo pipefail
# Comparar mismo par de máquinas y mismo número de flujos por rutas DIRECTA / VPN.
# Ejecutar en CLIENTE con iperf3 y un iperf3 -s en un recurso interno.
HOST="${1:-}"
ETIQUETA="${2:-}"
if [[ -z "$HOST" || "$ETIQUETA" != directa && "$ETIQUETA" != vpn ]]; then
  echo 'Uso: bash bench/scripts/medir_iperf.sh IP_DESTINO directa|vpn' >&2; exit 2
fi
mkdir -p bench/resultados
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
iperf3 -c "$HOST" -t 20 -P 4 -J > "bench/resultados/${ETIQUETA}_${TIMESTAMP}.json"
echo "Medición guardada. Repite contra el MISMO recurso con idénticas condiciones."
