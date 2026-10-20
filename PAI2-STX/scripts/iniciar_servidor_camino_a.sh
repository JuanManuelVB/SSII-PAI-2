#!/usr/bin/env bash
# Arranque manual NO destructivo: TLS 1.3/mTLS 9443 + registro RF1 8444.
# No arranca OpenVPN, no regenera la CA y no modifica usuarios/certificados.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
unset BYODSEC_VPN_REST BYODSEC_VPN_DEFAULT_DENY BYODSEC_AS_URL BYODSEC_AS_ADMIN_PASSWORD

if [[ -x "$ROOT/.venv-wsl/bin/python" ]]; then
    PY="$ROOT/.venv-wsl/bin/python"
elif [[ -x "$HOME/.local/share/byodsec/venv/bin/python" ]]; then
    PY="$HOME/.local/share/byodsec/venv/bin/python"
else
    echo 'ERROR: No hay entorno Python de WSL (.venv-wsl o ~/.local/share/byodsec/venv).' >&2
    echo 'Activa/instala el entorno Python ya utilizado en el proyecto antes de arrancar.' >&2
    exit 1
fi
for file in pki/ca/ca.crt pki/ca/ca.key pki/server/server.crt pki/server/server.key; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Falta $file. Se conserva la PKI actual, sin regenerar claves." >&2
        exit 1
    fi
done
if [[ ! -f src/recursos/rutas.py ]]; then
    echo 'AVISO: Falta src/recursos/rutas.py. Instala el parche Camino A para usar opcion 9.' >&2
fi

PIDS=()
cleanup() {
    trap - EXIT INT TERM
    if ((${#PIDS[@]})); then
        echo
        echo '[BYODSEC] Cerrando servicios...'
        kill "${PIDS[@]}" 2>/dev/null || true
        wait "${PIDS[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "[BYODSEC] Python WSL: $PY"
echo '[BYODSEC] Camino A: sin OpenVPN, no se regeneran certificados.'
echo '[BYODSEC] Iniciando gateway TLS 1.3 con mTLS en 127.0.0.1:9443...'
"$PY" -m src.gateway.ejecutar --host 127.0.0.1 --port 9443 &
PIDS+=("$!")
echo '[BYODSEC] Iniciando registro de dispositivos TLS 1.3 en 127.0.0.1:8444...'
"$PY" -m src.gateway.ejecutar_registro --host 127.0.0.1 --port 8444 &
PIDS+=("$!")

# Confirmar que ambos estan en ejecucion y escuchando antes de anunciar exito.
READY=0
for _ in {1..40}; do
    if ! kill -0 "${PIDS[0]}" 2>/dev/null || ! kill -0 "${PIDS[1]}" 2>/dev/null; then
        echo '[ERROR] Uno de los servicios ha terminado. Comprueba el error anterior.' >&2
        exit 1
    fi
    if (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && (echo > /dev/tcp/127.0.0.1/8444) 2>/dev/null; then
        READY=1
        break
    fi
    sleep 0.5
done
if ((READY == 0)); then
    echo '[ERROR] Los puertos 9443 y 8444 no estan disponibles; comprueba si hay otros servidores abiertos.' >&2
    exit 1
fi
printf '\n[OK] Gateway mTLS activo: https://localhost:9443\n'
printf '[OK] Registro RF1 activo: https://localhost:8444\n'
printf 'Deja esta ventana abierta; inicia ahora INICIAR_CLIENTE_BYODSEC.cmd.\n'
printf 'Para detener los servicios: Ctrl+C.\n\n'
wait -n "${PIDS[@]}"
RESULT=$?
echo "[BYODSEC] Un servicio ha terminado (codigo $RESULT). Cerrando el otro." >&2
exit "$RESULT"
