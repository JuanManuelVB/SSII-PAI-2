#!/usr/bin/env bash
# RS4 (manual): captura 60 s de tráfico VPN/TLS en la interfaz EXTERNA (no tun/as0t*).
# Uso: sudo bash scripts/manual/capturar_trafico.sh eth0
# Abrir el .pcap con Wireshark: debe verse TLS 1.3 / OpenVPN cifrado, nunca credenciales.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then echo "Uso: sudo bash scripts/manual/capturar_trafico.sh eth0" >&2; exit 2; fi
case "$IFACE" in *[!a-zA-Z0-9_.:-]*) echo "Nombre de interfaz inválido" >&2; exit 2;; esac
mkdir -p evidencias/pcap
OUT="evidencias/pcap/vpn_exterior_$(date -u +%Y%m%dT%H%M%SZ).pcap"
echo "Capturando 60 segundos en $IFACE (puertos 1194/443/943/9443/8444)..."
timeout 60 tcpdump -i "$IFACE" -w "$OUT" \
  'udp port 1194 or tcp port 443 or udp port 443 or tcp port 943 or tcp port 9443 or tcp port 8444' || true
echo "Archivo generado: $OUT (no se incluye en el ZIP salvo --con-pcap: puede contener IP)"
