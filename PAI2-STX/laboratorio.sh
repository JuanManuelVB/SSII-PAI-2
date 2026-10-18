#!/usr/bin/env bash
# =============================================================================
#  BYODSEC (PAI-2, SSII) · ÚNICO punto de entrada del laboratorio
#
#  Desde PowerShell, en la carpeta del proyecto:   wsl bash laboratorio.sh
#  Dentro de Ubuntu (WSL2 o nativo):               bash laboratorio.sh
#
#  Sin argumentos monta TODO el laboratorio, ejecuta TODAS las pruebas, guarda
#  las evidencias y abre el menú del cliente. Es idempotente: se puede relanzar.
# =============================================================================
set -Eeuo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$DIR/scripts"

uso() {
  cat <<'EOF'
Uso: bash laboratorio.sh [orden] [opciones]

Órdenes:
  todo       (por defecto) instalar + arrancar + probar + menú del cliente
  instalar   dependencias, PKI, 300 usuarios RF5 y OpenVPN Access Server
  arrancar   gateway mTLS :9443, registro RF1 :8444 y reconciliador RF4
  probar     pytest + auditoría PKI + ataques TLS + RS2 real + E2E real
  menu       consola interactiva del cliente BYODSEC (RF1 RF2 RF4 RF5 VPN)
  estado     diagnóstico de servicios, puertos y última batería de pruebas
  parar      detiene el gateway y el registro (Access Server sigue activo)
  entregar   genera ../PAI2-STX.zip limpio (sin secretos, venv ni SQLite)

Opciones:
  --sin-vpn   sin Access Server: solo RF1/RF2/RF4/RF5 + mTLS (diagnóstico)
  --sin-menu  no abrir el menú al terminar «todo»
EOF
}

orden=todo
SIN_MENU="${BYODSEC_SIN_MENU:-0}"
for arg in "$@"; do
  case "$arg" in
    todo|instalar|arrancar|probar|menu|estado|parar|entregar) orden="$arg" ;;
    --sin-vpn) export BYODSEC_SIN_VPN=1 ;;
    --sin-menu) SIN_MENU=1 ;;
    -h|--help|ayuda) uso; exit 0 ;;
    *) uso; exit 2 ;;
  esac
done

instalar() {
  bash "$S/1_dependencias.sh"
  bash "$S/2_pki_y_usuarios.sh"
  if [[ "${BYODSEC_SIN_VPN:-0}" == 1 ]]; then
    printf '\n[BYODSEC] Paso 3/5 · Access Server omitido (--sin-vpn)\n'
  else
    bash "$S/3_access_server.sh"
  fi
}

menu() {
  local vpn=1
  [[ "${BYODSEC_SIN_VPN:-0}" == 1 ]] && vpn=0
  cd "$DIR"
  BYODSEC_VPN_REST="$vpn" "$HOME/.local/share/byodsec/venv/bin/python" \
    -m src.client.interfaz --url https://localhost:9443 --registro-url https://localhost:8444
}

case "$orden" in
  instalar) instalar ;;
  arrancar) bash "$S/4_servicios.sh" ;;
  probar)   bash "$S/5_pruebas.sh" ;;
  menu)     menu ;;
  estado)   bash "$S/estado.sh" ;;
  parar)    bash "$S/parar.sh" ;;
  entregar) bash "$S/empaquetar_entrega.sh" ;;
  todo)
    instalar
    bash "$S/4_servicios.sh"
    resultado=0
    bash "$S/5_pruebas.sh" || resultado=$?
    bash "$S/estado.sh" --resumen
    if [[ -t 0 && -t 1 && "$SIN_MENU" != 1 ]]; then
      printf '\n[BYODSEC] Abriendo el menú del cliente (salir con 0)...\n'
      menu || true
    fi
    exit "$resultado"
    ;;
esac
