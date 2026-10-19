#!/usr/bin/env bash
# Lanzador del servidor BYODSEC ya instalado, sin reinstalar Access Server.
# Recibe contraseña administrativa solo por stdin desde Windows DPAPI.
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if ! IFS= read -r BYODSEC_AS_ADMIN_PASSWORD; then
  echo '[ERROR] No se recibió la contraseña desde el lanzador Windows.' >&2
  exit 1
fi
# PowerShell 5.1 puede enviar CRLF al proceso nativo; quitar SOLO el CR final.
BYODSEC_AS_ADMIN_PASSWORD="${BYODSEC_AS_ADMIN_PASSWORD%$'\r'}"
if [[ -z "$BYODSEC_AS_ADMIN_PASSWORD" ]]; then
  echo '[ERROR] La contraseña recibida está vacía.' >&2
  exit 1
fi
export BYODSEC_AS_ADMIN_PASSWORD
export BYODSEC_AS_URL='https://localhost:943'
export BYODSEC_AS_ADMIN_USER='openvpn'
export BYODSEC_AS_CA_BUNDLE="$HOME/.config/byodsec/access-server-ca.crt"
export BYODSEC_VPN_REST=1
export BYODSEC_VPN_DEFAULT_DENY=confirmed

if [[ -x "$ROOT/.venv-wsl/bin/python" ]]; then
  PY="$ROOT/.venv-wsl/bin/python"
elif [[ -x "$HOME/.local/share/byodsec/venv/bin/python" ]]; then
  PY="$HOME/.local/share/byodsec/venv/bin/python"
else
  echo '[ERROR] Falta el entorno virtual Python (.venv-wsl o ~/.local/share/byodsec/venv).' >&2
  exit 1
fi

if [[ ! -r "$BYODSEC_AS_CA_BUNDLE" ]]; then
  echo '[ERROR] Falta la CA de confianza de Access Server:' >&2
  echo "  $BYODSEC_AS_CA_BUNDLE" >&2
  echo 'Copia SOLO la CA publica correcta; no desactives la verificacion TLS.' >&2
  exit 1
fi
if ! systemctl is-active --quiet openvpnas; then
  echo '[ERROR] OpenVPN Access Server esta detenido.' >&2
  echo 'Abre Ubuntu y ejecuta: sudo systemctl start openvpnas' >&2
  echo 'Una vez por instalacion puedes usar: sudo systemctl enable openvpnas' >&2
  exit 1
fi
if [[ ! -f pki/server/server.crt || ! -f pki/server/server.key ]]; then
  echo '[ERROR] Faltan certificados del gateway BYODSEC en pki/server/.' >&2
  exit 1
fi

# No enmascaramos un fallo real de autenticacion/CA.
if ! "$PY" -m tools.comprobar_access_server; then
  echo '[ERROR] Fallo la autenticacion REST con Access Server.' >&2
  exit 1
fi

"$PY" - <<'PY'
import socket, sys
ocupados=[]
for port in (9443, 8444):
    sock=socket.socket()
    sock.settimeout(0.5)
    try:
        if sock.connect_ex(('127.0.0.1', port)) == 0:
            ocupados.append(str(port))
    finally:
        sock.close()
if ocupados:
    print('[ERROR] Puertos ya utilizados: '+', '.join(ocupados))
    print('Deten los servidores iniciados manualmente antes de usar este lanzador.')
    sys.exit(1)
PY

rf1_pid=''
gateway_pid=''
limpiar() {
  trap - EXIT
  [[ -n "$gateway_pid" ]] && kill "$gateway_pid" 2>/dev/null || true
  [[ -n "$rf1_pid" ]] && kill "$rf1_pid" 2>/dev/null || true
  [[ -n "$gateway_pid" ]] && wait "$gateway_pid" 2>/dev/null || true
  [[ -n "$rf1_pid" ]] && wait "$rf1_pid" 2>/dev/null || true
}
trap limpiar EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo '[BYODSEC] Arrancando registro RF1: https://localhost:8444'
"$PY" -m src.gateway.ejecutar_registro --port 8444 &
rf1_pid=$!
echo '[BYODSEC] Arrancando RF2/RF4 + REST VPN: https://localhost:9443'
"$PY" -m src.gateway.ejecutar --port 9443 &
gateway_pid=$!

sleep 3
if ! kill -0 "$rf1_pid" 2>/dev/null || ! kill -0 "$gateway_pid" 2>/dev/null; then
  echo '[ERROR] Algun servicio BYODSEC no ha arrancado. Revisa los errores anteriores.' >&2
  exit 1
fi
echo '[BYODSEC] Servidores iniciados. Para abrir la interfaz: Abrir_Interfaz_BYODSEC.cmd'
echo '[BYODSEC] Para detener RF1 y RF2/RF4 pulsa Ctrl+C en esta ventana.'
wait -n "$rf1_pid" "$gateway_pid" || true
echo '[BYODSEC] Uno de los servicios ha terminado; deteniendo el otro.'
exit 1
