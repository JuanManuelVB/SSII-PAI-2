#!/usr/bin/env bash
set -euo pipefail
# Tráfico del laboratorio: interfaz WAN real, NO el túnel interno tun0.
# Requiere tcpdump y permisos de administrador; no contiene contraseñas.
IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then echo "Uso: sudo bash vpn/scripts/capturar_trafico.sh eth0" >&2; exit 2; fi
case "$IFACE" in *[!a-zA-Z0-9_.:-]*) echo "Nombre de interfaz inválido" >&2; exit 2;; esac
mkdir -p evidencias/pcap
OUT="evidencias/pcap/vpn_exterior_$(date -u +%Y%m%dT%H%M%SZ).pcap"
echo "Capturando 60 segundos en $IFACE. Guarda el fichero privado si contiene IP identificables."
timeout 60 tcpdump -i "$IFACE" -w "$OUT" 'udp port 1194 or tcp port 443 or udp port 443 or tcp port 943'
echo "Archivo generado: $OUT"
