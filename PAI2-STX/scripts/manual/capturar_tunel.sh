#!/usr/bin/env bash
# RS4 (manual): captura 60 s DENTRO del túnel (interfaz as0t*/tun) mientras se
# accede al recurso interno. Sirve para contrastar con capturar_trafico.sh:
#   - fuera (interfaz pública): todo cifrado (TLS 1.3 / OpenVPN), ilegible.
#   - dentro del túnel: el mismo tráfico aparece en claro -> demuestra que viajó
#     cifrado por la red pública y solo se descifra tras la VPN.
#
# Uso: sudo bash scripts/manual/capturar_tunel.sh as0t0
# (ver el nombre real con:  ip -o link show | grep -E 'as0t|tun')
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Uso: sudo bash scripts/manual/capturar_tunel.sh <interfaz_tunel>" >&2
  echo "Interfaces disponibles:" >&2
  ip -o link show 2>/dev/null | awk -F': ' '{print "  " $2}' >&2 || true
  exit 2
fi
case "$IFACE" in *[!a-zA-Z0-9_.:-]*) echo "Nombre de interfaz inválido" >&2; exit 2;; esac
mkdir -p evidencias/pcap
OUT="evidencias/pcap/tunel_interno_$(date -u +%Y%m%dT%H%M%SZ).pcap"
echo "Capturando 60 s DENTRO del túnel en $IFACE..."
echo "En otra terminal, accede ahora al recurso interno (tools.probar_tunel --fase con-vpn)."
timeout 60 tcpdump -i "$IFACE" -w "$OUT" 2>/dev/null || true
echo "Archivo generado: $OUT"
echo "En Wireshark debe verse en claro el HTTP al recurso interno; compáralo con"
echo "la captura exterior (capturar_trafico.sh), donde el mismo tráfico va cifrado."
