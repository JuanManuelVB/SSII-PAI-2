#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables usadas por los scripts que cargan este fichero
# BYODSEC: rutas y funciones comunes de todos los scripts del laboratorio.
# Se carga con «source»; no se ejecuta por separado.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Secretos y estado LOCAL, siempre fuera del repositorio (no se entregan).
LAB="$HOME/.config/byodsec"                 # contraseña admin AS, CA web, perfiles .ovpn
STATE="$HOME/.local/state/byodsec"          # PID y logs de los servicios
VENV="$HOME/.local/share/byodsec/venv"      # entorno Python en disco Linux (rápido)
PY="$VENV/bin/python"
ENVFILE="$LAB/laboratorio.env"
MARKER="$LAB/instalacion.local.ok"
OWNER="$LAB/instalador-es-propietario"
SACLI=/usr/local/openvpn_as/scripts/sacli

USUARIO_DEMO=rf5_inv_001
PUERTO_GATEWAY=9443
PUERTO_REGISTRO=8444
EVIDENCIAS="$ROOT/evidencias"
# Modo sin Access Server (solo RF1/RF2/RF4/RF5 + mTLS): BYODSEC_SIN_VPN=1
SIN_VPN="${BYODSEC_SIN_VPN:-0}"

if [[ -t 1 ]]; then C='\033[1;36m'; V='\033[32m'; A='\033[33m'; R='\033[1;31m'; N='\033[0m'
else C=''; V=''; A=''; R=''; N=''; fi

log()   { printf "\n${C}[BYODSEC]${N} %s\n" "$*"; }
ok()    { printf "  ${V}OK${N} %s\n" "$*"; }
aviso() { printf "  ${A}AVISO${N} %s\n" "$*" >&2; }
die()   { printf "\n${R}[BYODSEC][ERROR]${N} %s\n" "$*" >&2; exit 1; }
trap 'die "Fallo inesperado en ${BASH_SOURCE[0]##*/}:${LINENO} (orden: ${BASH_COMMAND%%$'"'"'\n'"'"'*})"' ERR

preparar_directorios_privados() {
  mkdir -p "$LAB/clients" "$STATE"
  chmod 700 "$LAB" "$LAB/clients" "$STATE"
}

exigir_python() {
  [[ -x "$PY" ]] || die "Falta el entorno Python del laboratorio. Ejecuta: bash laboratorio.sh instalar"
}

# Carga BYODSEC_AS_* (credenciales de Access Server) si el laboratorio usa VPN.
cargar_entorno() {
  if [[ "$SIN_VPN" == 1 ]]; then
    export BYODSEC_VPN_REST=0
    return 0
  fi
  [[ -r "$ENVFILE" ]] || die "No existe $ENVFILE. Ejecuta antes: bash laboratorio.sh instalar"
  set -a
  # shellcheck disable=SC1090  # fichero generado por 3_access_server.sh (chmod 600)
  source "$ENVFILE"
  set +a
}

# Pide sudo una vez y lo mantiene vivo mientras dure el script.
mantener_sudo() {
  sudo -v || die 'Se necesita sudo para instalar paquetes y Access Server'
  ( while kill -0 "$$" 2>/dev/null; do sudo -n true; sleep 50; done ) 2>/dev/null &
}

puerto_abierto() { (echo > "/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

esperar_puerto() {
  local puerto="$1" segundos="${2:-20}"
  for _ in $(seq 1 "$segundos"); do
    puerto_abierto "$puerto" && return 0
    sleep 1
  done
  return 1
}

proceso_vivo() { [[ -f "$1" ]] && kill -0 "$(cat "$1")" 2>/dev/null; }
