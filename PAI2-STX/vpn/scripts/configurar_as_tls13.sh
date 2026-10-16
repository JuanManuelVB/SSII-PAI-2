#!/usr/bin/env bash
set -euo pipefail
# SOLO en el servidor de laboratorio con OpenVPN Access Server >= 3.2.
# Hace falta sudo y aceptar que reiniciará el servicio VPN.
SACLI=/usr/local/openvpn_as/scripts/sacli
if [[ ! -x "$SACLI" ]]; then echo "No encuentro Access Server: $SACLI" >&2; exit 1; fi
if [[ "${1:-}" != "--apply" ]]; then
  echo "Vista previa: fijaría mínimo TLS 1.3 para VPN y Web." 
  echo "Para aplicar: sudo bash vpn/scripts/configurar_as_tls13.sh --apply"
  exit 0
fi
"$SACLI" --key vpn.server.tls_version_min --value 1.3 ConfigPut
"$SACLI" --key cs.tls_version_min --value 1.3 ConfigPut
"$SACLI" start
printf 'TLS1.3 mínimo solicitado. Confirmar en panel y conexiones reales.\n'
