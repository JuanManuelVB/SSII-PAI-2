#!/usr/bin/env bash
# Paso 4: arranca los servicios BYODSEC en segundo plano.
#   - Gateway RF2/RF4/VPN  TLS 1.3 + mTLS   https://localhost:9443
#   - Registro RF1         TLS 1.3          https://localhost:8444
#   - Reconciliador RF4    systemd timer que cierra por REST las VPN de sesiones caducadas
source "$(dirname "${BASH_SOURCE[0]}")/comun.sh"
exigir_python
preparar_directorios_privados
cargar_entorno
[[ -f pki/server/server.crt ]] || die 'Falta la PKI. Ejecuta: bash laboratorio.sh instalar'

arrancar() {  # nombre puerto modulo
  local nombre="$1" puerto="$2" modulo="$3"
  local pid="$STATE/$1.pid" registro="$STATE/$1.log"
  if proceso_vivo "$pid"; then
    ok "$nombre ya en marcha (PID $(cat "$pid")) en el puerto $puerto"
    return 0
  fi
  if puerto_abierto "$puerto"; then
    die "El puerto $puerto está ocupado por otro proceso; no se sustituye."
  fi
  nohup "$PY" -m "$modulo" --port "$puerto" >"$registro" 2>&1 </dev/null &
  echo "$!" > "$pid"
  if ! esperar_puerto "$puerto" 20 || ! proceso_vivo "$pid"; then
    tail -n 20 "$registro" >&2
    die "No ha arrancado $nombre (log: $registro)"
  fi
  ok "$nombre en https://localhost:$puerto (PID $(cat "$pid"), log: $registro)"
}

instalar_reconciliador() {
  # Las rutas pueden tener espacios (carpetas de Windows): se citan para systemd.
  local servicio=/etc/systemd/system/byodsec-reconciliar.service
  local temporizador=/etc/systemd/system/byodsec-reconciliar.timer
  printf '%s\n' \
    '[Unit]' \
    'Description=BYODSEC - cerrar por REST las VPN cuya sesión RF2 caducó o fue revocada' \
    'After=network-online.target openvpnas.service' \
    '' \
    '[Service]' \
    'Type=oneshot' \
    "User=${USER:-$(id -un)}" \
    "WorkingDirectory=$ROOT" \
    "EnvironmentFile=$ENVFILE" \
    "ExecStart=\"$PY\" -m src.vpn_rest_as.reconciliar" \
    'NoNewPrivileges=true' | sudo tee "$servicio" >/dev/null || return 1
  printf '%s\n' \
    '[Unit]' \
    'Description=BYODSEC - reconciliación RF4 cada minuto' \
    '' \
    '[Timer]' \
    'OnBootSec=60sec' \
    'OnUnitActiveSec=60sec' \
    'Unit=byodsec-reconciliar.service' \
    '' \
    '[Install]' \
    'WantedBy=timers.target' | sudo tee "$temporizador" >/dev/null || return 1
  sudo systemctl daemon-reload || return 1
  sudo systemctl enable --now byodsec-reconciliar.timer >/dev/null 2>&1 || return 1
}

log 'Paso 4/5 · Servicios BYODSEC'
if [[ "${BYODSEC_VPN_REST:-0}" == 1 ]]; then
  ok 'Modo completo: RF4 bloquea y desconecta la VPN por la API REST de Access Server'
else
  aviso 'Modo sin VPN: RF4 solo revoca la sesión de aplicación'
fi
arrancar gateway "$PUERTO_GATEWAY" src.gateway.ejecutar
arrancar registro "$PUERTO_REGISTRO" src.gateway.ejecutar_registro

if [[ "$SIN_VPN" != 1 ]]; then
  log 'Paso 4/5 · Reconciliador RF4 (cada minuto, systemd)'
  mantener_sudo
  if instalar_reconciliador; then
    ok 'byodsec-reconciliar.timer activo (journalctl -u byodsec-reconciliar)'
  else
    aviso 'No se pudo activar el reconciliador; el logout RF4 explícito sigue funcionando.'
  fi
fi
