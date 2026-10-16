#!/usr/bin/env bash
# BYODSEC: un solo comando dentro de Ubuntu/WSL2 para instalar y levantar un laboratorio independiente.
# Requisitos previos: WSL2 + Ubuntu 24.04/26.04 con systemd; repo ya clonado.
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
LAB="$HOME/.config/byodsec"
STATE="$HOME/.local/state/byodsec"
ENVFILE="$LAB/laboratorio.env"
MARKER="$LAB/instalacion.local.ok"
OWNER="$LAB/instalador-es-propietario"
AS='/usr/local/openvpn_as/scripts/sacli'
PY="$ROOT/.venv-wsl/bin/python"
mkdir -p "$LAB" "$STATE" "$LAB/clients"
chmod 700 "$LAB" "$STATE" "$LAB/clients"

log() { printf '\n[BYODSEC] %s\n' "$*"; }
die() { printf '\n[BYODSEC][ERROR] %s\n' "$*" >&2; exit 1; }
needs_file() { [[ -f "$1" ]] || die "No existe $1. Aplica el parche sobre el proyecto integrado."; }
needs_file "$ROOT/src/vpn_rest_as/ejecutar.py"
needs_file "$ROOT/src/rf5/cli.py"
needs_file "$ROOT/pki/scripts/pki.py"
# Protección adicional para los archivos generados: no sobrescribir el .gitignore
# del equipo. Si el repositorio ya sigue secretos, detenerse antes de producir más.
touch "$ROOT/.gitignore"
for patron in '.venv-wsl/' '*.ovpn' '*.sqlite3' '*.sqlite3-*' \
  'pki/**/*.key' 'pki/**/*.crt' 'pki/**/*.pem' \
  'pki/clients/rf5/credenciales.csv'; do
  grep -Fxq -- "$patron" "$ROOT/.gitignore" || printf '%s\n' "$patron" >> "$ROOT/.gitignore"
done
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  secretos="$(git ls-files -- pki/ca/ca.key pki/server/server.key pki/clients/rf5/credenciales.csv data/rf1.sqlite3)"
  [[ -z "$secretos" ]] || die 'Ya hay secretos/base de datos seguidos por Git. Limpia su seguimiento e historial antes de arrancar este laboratorio.'
fi
command -v sudo >/dev/null || die 'Falta sudo'
command -v apt-get >/dev/null || die 'Este script requiere Ubuntu en WSL2'
[[ "$(ps -p 1 -o comm= | tr -d ' ')" == 'systemd' ]] || die 'WSL no está usando systemd. Habilítalo y reinicia WSL.'
[[ -c /dev/net/tun ]] || die 'El dispositivo /dev/net/tun no está disponible en WSL.'
. /etc/os-release
[[ "$ID" == 'ubuntu' ]] || die 'Solo se admite Ubuntu en este instalador.'
case "${VERSION_CODENAME:-}" in
  noble|resolute) CODENAME="$VERSION_CODENAME" ;;
  *) die "Ubuntu $VERSION_ID no está validado por este instalador (24.04 o 26.04)." ;;
esac
case "$(dpkg --print-architecture)" in
  amd64|arm64) ARCH="$(dpkg --print-architecture)" ;;
  *) die 'Arquitectura no soportada por este instalador.' ;;
esac

# No sobrescribir por accidente un Access Server que se configuró fuera de este laboratorio.
if [[ ! -f "$MARKER" && ! -f "$OWNER" ]] && dpkg-query -W -f='${Status}' openvpn-as 2>/dev/null | grep -q 'install ok installed'; then
  die "Ya existe Access Server sin marcador BYODSEC. No sobrescribimos tu servidor. Usa una distribución WSL limpia para un laboratorio independiente."
fi

log 'Dependencias de Ubuntu y entorno virtual Python'
sudo -v
# A partir de aquí las siguientes ejecuciones pertenecen a ESTE laboratorio.
printf 'lab-propio=1\n' > "$OWNER"
chmod 600 "$OWNER"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-pip ca-certificates curl wget gnupg openssl iproute2
if [[ ! -x "$PY" ]]; then python3 -m venv .venv-wsl; fi
"$PY" -m pip install -q -r requirements.txt -r requirements-interfaz.txt

# Los 300 nombres son los MISMOS en cada copia, pero las credenciales son locales y aleatorias.
log 'PKI corporativa, SQLite y 300 usuarios RF5 de laboratorio'
[[ -f pki/ca/ca.crt ]] || "$PY" -m pki.scripts.pki crear-ca
[[ -f pki/server/server.crt ]] || "$PY" -m pki.scripts.pki emitir-servidor --nombre localhost
"$PY" -m src.rf5.cli precargar --total 300
"$PY" -m src.rf5.cli certificados --limite 300
"$PY" -m src.rf5.cli resumen

if [[ ! -f "$MARKER" ]]; then
  log 'Instalación oficial de OpenVPN Access Server'
  sudo install -d -m 755 /etc/apt/keyrings
  sudo wget -qO /etc/apt/keyrings/as-repository.asc https://packages.openvpn.net/as-repo-public.asc
  echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/as-repository.asc] http://packages.openvpn.net/as/debian $CODENAME main" | sudo tee /etc/apt/sources.list.d/openvpn-as-repo.list >/dev/null
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn-as
  sudo systemctl enable --now openvpnas
  sudo systemctl is-active --quiet openvpnas || die 'Access Server no arrancó; consulta journalctl -u openvpnas'

  log 'Certificado HTTPS local estricto para Access Server'
  # Esta CA es SOLO para HTTPS administrativo. Nunca se sustituyen certificados de RF1/RF2.
  sudo install -d -m 700 /etc/byodsec-local-webtls
  sudo tee /etc/byodsec-local-webtls/ca.cnf >/dev/null <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[dn]
CN = BYODSEC Local Web CA
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  sudo openssl req -x509 -newkey rsa:3072 -noenc -sha256 -days 1825 \
    -config /etc/byodsec-local-webtls/ca.cnf \
    -keyout /etc/byodsec-local-webtls/ca.key \
    -out /etc/byodsec-local-webtls/ca.crt >/dev/null 2>&1
  sudo openssl req -new -newkey rsa:3072 -noenc \
    -keyout /etc/byodsec-local-webtls/server.key \
    -out /etc/byodsec-local-webtls/server.csr -subj /CN=localhost >/dev/null 2>&1
  sudo tee /etc/byodsec-local-webtls/server.cnf >/dev/null <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF
  SERIAL="$(openssl rand -hex 16)"
  sudo openssl x509 -req -in /etc/byodsec-local-webtls/server.csr \
    -CA /etc/byodsec-local-webtls/ca.crt -CAkey /etc/byodsec-local-webtls/ca.key \
    -set_serial "0x${SERIAL}" -out /etc/byodsec-local-webtls/server.crt \
    -days 365 -sha256 -extfile /etc/byodsec-local-webtls/server.cnf >/dev/null 2>&1
  sudo openssl verify -x509_strict -purpose sslserver -verify_hostname localhost \
    -CAfile /etc/byodsec-local-webtls/ca.crt /etc/byodsec-local-webtls/server.crt
  sudo chmod 600 /etc/byodsec-local-webtls/{ca,server}.key
  sudo "$AS" --key cs.priv_key --value_file /etc/byodsec-local-webtls/server.key ConfigPut >/dev/null
  sudo "$AS" --key cs.cert --value_file /etc/byodsec-local-webtls/server.crt ConfigPut >/dev/null
  sudo "$AS" --key cs.ca_bundle --value_file /etc/byodsec-local-webtls/ca.crt ConfigPut >/dev/null
  sudo "$AS" --key openapi.web_access --value 1 ConfigPut >/dev/null
  sudo "$AS" --key auth.module.type --value local ConfigPut >/dev/null

  # Crear admin único LOCAL (no compartir con otros equipos).
  ADMIN_PASSWORD="$($PY -c 'import secrets; print(secrets.token_urlsafe(32))')"
  sudo "$AS" --user openvpn --key prop_superuser --value true UserPropPut >/dev/null
  sudo "$AS" --user openvpn --key user_auth_type --value local UserPropPut >/dev/null
  sudo "$AS" --user openvpn --new_pass "$ADMIN_PASSWORD" SetLocalPassword >/dev/null
  sudo "$AS" start >/dev/null
  sudo install -m 644 /etc/byodsec-local-webtls/ca.crt "$LAB/access-server-ca.crt"
  printf 'BYODSEC_AS_URL=https://localhost:943\nBYODSEC_AS_ADMIN_USER=openvpn\nBYODSEC_AS_ADMIN_PASSWORD=%s\nBYODSEC_AS_CA_BUNDLE=%s\nBYODSEC_VPN_REST=1\nBYODSEC_VPN_DEFAULT_DENY=confirmed\n' \
    "$ADMIN_PASSWORD" "$LAB/access-server-ca.crt" > "$ENVFILE"
  chmod 600 "$ENVFILE"
  unset ADMIN_PASSWORD
  # El marcador se escribe ANTES de crear usuarios para que un fallo permita reintentar
  # sin regenerar la CA web o resetear una contraseña administrativa existente.
  printf 'byodsec-lab-version=1\n' > "$MARKER"
  chmod 600 "$MARKER"
fi

log 'Comprobando API REST oficial de Access Server'
[[ -r "$ENVFILE" ]] || die "No existe $ENVFILE"
set -a
# Archivo generado por este script, solo accesible al propietario.
# shellcheck disable=SC1090
source "$ENVFILE"
set +a
sudo systemctl start openvpnas
OK_REST=0
for intento in $(seq 1 20); do
  if "$PY" -m tools.comprobar_access_server; then OK_REST=1; break; fi
  sleep 3
done
[[ "$OK_REST" == 1 ]] || die 'La API REST no está preparada; comprueba journalctl -u openvpnas'

log 'Provisionar el usuario DEMO rf5_inv_001 con el mismo nombre en todos los equipos'
# Idempotencia: solo crear el usuario de demostración en el primer aprovisionamiento.
if [[ ! -f "$LAB/demo-provisionado.ok" ]]; then
  "$PY" -m src.vpn_rest_as.provision --limit 1 --apply
  # Access Server exige una contraseña VPN local además del RF2. Para pruebas locales
  # usamos la contraseña RF5 generada en ESTE equipo; no se envía a GitHub.
  RF5_PASSWORD="$($PY - <<'PY'
import csv
from pathlib import Path
with Path('pki/clients/rf5/credenciales.csv').open(newline='',encoding='utf-8') as f:
    matches=[r['password'] for r in csv.DictReader(f) if r['username']=='rf5_inv_001']
assert len(matches)==1, 'Falta la credencial local rf5_inv_001'
print(matches[0])
PY
)"
  sudo "$AS" --user rf5_inv_001 --key user_auth_type --value local UserPropPut >/dev/null
  sudo "$AS" --user rf5_inv_001 --new_pass "$RF5_PASSWORD" SetLocalPassword >/dev/null
  unset RF5_PASSWORD
  sudo "$AS" start >/dev/null
  printf 'provisionado=1\n' > "$LAB/demo-provisionado.ok"
  chmod 600 "$LAB/demo-provisionado.ok"
fi

# Perfil individual de prueba por API REST. Si cambia el API en otra versión,
# no inventamos un perfil: queda fallo explícito, sin degradar la autenticación.
if [[ ! -s "$LAB/clients/rf5_inv_001.ovpn" ]]; then
  if ! "$PY" -m tools.generar_perfil_laboratorio --destino "$LAB/clients/rf5_inv_001.ovpn"; then
    printf "[BYODSEC][AVISO] Perfil VPN no generado: revisa la API REST /profiles/create. El servidor y la autenticación pueden arrancar.\n" >&2
  fi
fi

log 'Arrancar FastAPI BYODSEC sobre TLS 1.3/mTLS (localhost:9443)'
if [[ -f "$STATE/gateway.pid" ]] && kill -0 "$(cat "$STATE/gateway.pid")" 2>/dev/null; then
  log "Gateway ya iniciado (PID $(cat "$STATE/gateway.pid"))"
else
  if (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null; then
    die 'El puerto 9443 ya está ocupado por otro proceso. No lo sustituiremos.'
  fi
  nohup "$PY" -m src.vpn_rest_as.ejecutar --port 9443 \
    >"$STATE/gateway.log" 2>&1 < /dev/null &
  echo "$!" > "$STATE/gateway.pid"
  sleep 3
  kill -0 "$(cat "$STATE/gateway.pid")" 2>/dev/null || {
    tail -n 20 "$STATE/gateway.log" >&2
    die 'No ha arrancado el gateway mTLS.'
  }
fi

log 'Arrancar servicio de registro RF1 por HTTPS TLS 1.3 (localhost:8444)'
if [[ -f "$STATE/registro.pid" ]] && kill -0 "$(cat "$STATE/registro.pid")" 2>/dev/null; then
  log "Registro RF1 ya iniciado (PID $(cat "$STATE/registro.pid"))"
else
  if (echo > /dev/tcp/127.0.0.1/8444) 2>/dev/null; then
    die 'El puerto 8444 está ocupado por otro proceso; no lo sustituiremos.'
  fi
  nohup "$PY" -m src.gateway.ejecutar_registro --port 8444 \
    >"$STATE/registro.log" 2>&1 < /dev/null &
  echo "$!" > "$STATE/registro.pid"
  sleep 2
  kill -0 "$(cat "$STATE/registro.pid")" 2>/dev/null || {
    tail -n 20 "$STATE/registro.log" >&2
    die 'No ha arrancado el servidor de registro RF1.'
  }
fi

log 'LABORATORIO LISTO — credenciales y certificados únicos en este Ubuntu'
printf 'BYODSEC FastAPI RF2/RF4: https://localhost:9443\nRegistro RF1: https://localhost:8444\nAccess Server: https://localhost:943/admin/\n'
printf 'Usuario de pruebas (MISMO nombre en todos los PCs): rf5_inv_001\n'
printf 'Contraseña de usuario de prueba: consulta LOCALMENTE pki/clients/rf5/credenciales.csv\n'
printf 'Perfil VPN local: %s\n' "$LAB/clients/rf5_inv_001.ovpn"
printf 'Clave de administrador privada: %s (NO compartir)\n' "$ENVFILE"
printf 'Logs: %s/gateway.log\n' "$STATE"
printf '\nDesde Windows: py -m src.client.interfaz --url https://localhost:9443\n'
printf 'Para reiniciar el laboratorio, vuelve a ejecutar ESTE MISMO comando.\n'
if [[ -t 0 && "${BYODSEC_SIN_MENU:-0}" != "1" ]]; then
  printf '\n[BYODSEC] Abriendo menú interactivo desde WSL...\n'
  "$PY" -m src.client.interfaz --url https://localhost:9443
fi
