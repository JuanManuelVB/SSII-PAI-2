#!/usr/bin/env bash
# Diagnóstico del laboratorio. Con --resumen muestra solo los datos de acceso.
source "$(dirname "${BASH_SOURCE[0]}")/comun.sh"
trap - ERR
set +e

estado_servicio() {  # nombre puerto
  local pid="$STATE/$1.pid"
  if proceso_vivo "$pid"; then ok "$1: en marcha (PID $(cat "$pid")) en https://localhost:$2"
  else aviso "$1: parado (bash laboratorio.sh arrancar)"; fi
}

perfil="$LAB/clients/$USUARIO_DEMO.ovpn"
log 'Datos de acceso del laboratorio'
printf '  Gateway RF2/RF4/VPN (mTLS) : https://localhost:%s\n' "$PUERTO_GATEWAY"
printf '  Registro RF1 (TLS 1.3)     : https://localhost:%s\n' "$PUERTO_REGISTRO"
if [[ "$SIN_VPN" != 1 ]]; then
  printf '  Access Server (admin)      : https://localhost:943/admin/  (usuario openvpn; clave en %s)\n' "$ENVFILE"
fi
printf '  Usuario de prueba          : %s (contraseña en pki/clients/rf5/credenciales.csv)\n' "$USUARIO_DEMO"
if [[ -s "$perfil" ]]; then
  printf '  Perfil OpenVPN (Linux)     : %s\n' "$perfil"
  command -v wslpath >/dev/null && printf '  Perfil OpenVPN (Windows)   : %s\n' "$(wslpath -w "$perfil")"
fi
printf '  Menú del cliente           : bash laboratorio.sh menu\n'
printf '  Evidencias                 : evidencias/logs/resumen_pruebas.txt\n'
[[ "${1:-}" == --resumen ]] && exit 0

log 'Sistema'
. /etc/os-release; ok "$PRETTY_NAME"
[[ -c /dev/net/tun ]] && ok '/dev/net/tun disponible' || aviso '/dev/net/tun no disponible'
[[ -x "$PY" ]] && ok "Python: $("$PY" --version)" || aviso 'Entorno Python sin instalar'

log 'Servicios'
estado_servicio gateway "$PUERTO_GATEWAY"
estado_servicio registro "$PUERTO_REGISTRO"
if command -v systemctl >/dev/null; then
  for unidad in openvpnas byodsec-reconciliar.timer; do
    printf '  %-26s %s\n' "$unidad:" "$(systemctl is-active "$unidad" 2>/dev/null | head -1)"
  done
fi
printf '  Puertos en escucha:\n'
ss -lntu 2>/dev/null | awk 'NR>1 && $5 ~ /:(943|9443|8444|1194|443)$/ {print "    " $1 " " $5}'

if [[ -f "$EVIDENCIAS/logs/resumen_pruebas.txt" ]]; then
  log 'Última batería de pruebas'
  sed 's/^/  /' "$EVIDENCIAS/logs/resumen_pruebas.txt"
fi
