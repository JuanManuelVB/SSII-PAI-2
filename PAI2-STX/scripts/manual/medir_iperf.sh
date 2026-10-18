#!/usr/bin/env bash
# RS3 (manual): rendimiento con y sin VPN contra el MISMO recurso (iperf3 -s en destino).
# Uso: bash scripts/manual/medir_iperf.sh IP_DESTINO directa|vpn
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
HOST="${1:-}"
ETIQUETA="${2:-}"
if [[ -z "$HOST" || ( "$ETIQUETA" != directa && "$ETIQUETA" != vpn ) ]]; then
  echo 'Uso: bash scripts/manual/medir_iperf.sh IP_DESTINO directa|vpn' >&2; exit 2
fi
mkdir -p bench/resultados
SALIDA="bench/resultados/${ETIQUETA}_$(date -u +%Y%m%dT%H%M%SZ).json"
iperf3 -c "$HOST" -t 20 -P 4 -J > "$SALIDA"
echo "Medición guardada en $SALIDA. Repite con la otra ruta en idénticas condiciones."
