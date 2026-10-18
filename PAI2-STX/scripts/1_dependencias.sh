#!/usr/bin/env bash
# Paso 1: comprobar Ubuntu/WSL2 e instalar dependencias del sistema y de Python.
source "$(dirname "${BASH_SOURCE[0]}")/comun.sh"

log 'Paso 1/5 · Comprobando el sistema'
command -v apt-get >/dev/null || die 'Este laboratorio requiere Ubuntu (por ejemplo, Ubuntu en WSL2)'
command -v sudo >/dev/null || die 'Falta sudo'
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die "Solo se admite Ubuntu (detectado: ${PRETTY_NAME:-desconocido})"
ok "$PRETTY_NAME"

es_wsl=0
grep -qi microsoft /proc/version 2>/dev/null && es_wsl=1
if [[ "$(ps -p 1 -o comm= | tr -d ' ')" != systemd ]]; then
  if [[ "$es_wsl" == 1 ]]; then
    mantener_sudo
    # Activa systemd en WSL conservando el resto de /etc/wsl.conf.
    sudo python3 - <<'PY'
import configparser, pathlib
ruta = pathlib.Path('/etc/wsl.conf')
cfg = configparser.ConfigParser()
cfg.read(ruta)
if not cfg.has_section('boot'):
    cfg.add_section('boot')
cfg.set('boot', 'systemd', 'true')
with ruta.open('w') as f:
    cfg.write(f)
PY
    die "systemd no estaba activo en WSL y se acaba de activar en /etc/wsl.conf.
       Ejecuta en PowerShell:  wsl --shutdown
       y vuelve a lanzar:      wsl bash laboratorio.sh"
  fi
  die 'El sistema no usa systemd (necesario para OpenVPN Access Server)'
fi
ok 'systemd activo'
if [[ "$SIN_VPN" != 1 ]]; then
  [[ -c /dev/net/tun ]] || die 'No existe /dev/net/tun: la VPN no puede crear interfaces en este sistema'
  ok '/dev/net/tun disponible'
fi

log 'Paso 1/5 · Paquetes de Ubuntu'
mantener_sudo
# Repara instalaciones previas con umask 077: apt lee las claves como el
# usuario _apt y falla con «The repository ... is not signed» si son 600.
for fichero in /etc/apt/keyrings/as-repository.asc /etc/apt/sources.list.d/openvpn-as-repo.list; do
  [[ -f "$fichero" ]] && sudo chmod 644 "$fichero"
done
[[ -d /etc/apt/keyrings ]] && sudo chmod 755 /etc/apt/keyrings
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  python3 python3-venv python3-pip ca-certificates curl gnupg openssl iproute2 \
  tcpdump iperf3 >/dev/null
ok 'python3-venv, openssl, curl, gnupg, iproute2, tcpdump, iperf3'

log 'Paso 1/5 · Entorno Python aislado'
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' \
  || die 'Se necesita Python 3.10 o superior'
mkdir -p "$(dirname "$VENV")"
[[ -x "$PY" ]] || python3 -m venv "$VENV"
"$PY" -m pip install -q --upgrade pip
"$PY" -m pip install -q -r requirements.txt
ok "Dependencias de requirements.txt instaladas en $VENV"
if [[ -d "$ROOT/.venv-wsl" ]]; then
  aviso "La carpeta antigua .venv-wsl ya no se usa; puedes borrarla."
fi
