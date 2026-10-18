#!/usr/bin/env bash
# Detiene el gateway y el registro RF1. Access Server y el reconciliador siguen
# como servicios systemd (sudo systemctl stop openvpnas byodsec-reconciliar.timer).
source "$(dirname "${BASH_SOURCE[0]}")/comun.sh"

log 'Deteniendo servicios BYODSEC'
for nombre in gateway registro; do
  pid="$STATE/$nombre.pid"
  if proceso_vivo "$pid"; then
    kill "$(cat "$pid")"
    ok "$nombre detenido"
  else
    ok "$nombre no estaba en marcha"
  fi
  rm -f "$pid"
done
