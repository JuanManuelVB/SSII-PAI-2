#!/usr/bin/env bash
# Paso 5: batería completa de pruebas y evidencias (no se detiene en el primer fallo).
#   1. pytest: batería unitaria/integración aislada (RF1 RF2 RF4 RF5 RS1 RS2 VPN y extra)
#   2. Auditoría RF1/RF5/RS1 de los 300 usuarios y certificados reales
#   3. Ataques controlados TLS (+10 %): CA falsa, sin certificado cliente, TLS 1.2
#   4. RS2 en los servicios en marcha: solo TLS 1.3 (versión y cipher suite negociadas)
#   5. E2E real RF1 -> RF2 -> VPN -> RF4 contra los servicios en marcha
#   6. API REST de Access Server operativa
# Resultados en evidencias/logs/ y resumen en evidencias/logs/resumen_pruebas.txt
source "$(dirname "${BASH_SOURCE[0]}")/comun.sh"
exigir_python
cargar_entorno
LOGS="$EVIDENCIAS/logs"
mkdir -p "$LOGS" "$EVIDENCIAS/ataques"
trap - ERR   # aquí se recogen los fallos uno a uno
set +e

declare -a NOMBRES=() ESTADOS=() FICHEROS=()
prueba() {  # nombre fichero_evidencia comando...
  local nombre="$1" fichero="$2"; shift 2
  log "Paso 5/5 · $nombre"
  "$@"
  local rc=$?
  NOMBRES+=("$nombre"); FICHEROS+=("${fichero#"$ROOT"/}")
  if [[ $rc == 0 ]]; then ESTADOS+=(PASS); ok "$nombre"; else ESTADOS+=(FAIL); aviso "$nombre: FALLO (código $rc)"; fi
}

# El conjunto de pytest no usa Access Server ni datos reales (conftest.py lo aísla).
prueba 'Pruebas automáticas (pytest)' "$LOGS/pytest.txt" \
  bash -c '"$0" -m pytest -q -rA --junitxml "$1" 2>&1 | tee "$2"; exit "${PIPESTATUS[0]}"' \
  "$PY" "$LOGS/pytest_junit.xml" "$LOGS/pytest.txt"

prueba 'Auditoría RF1/RF5/RS1: 300 usuarios y certificados' "$LOGS/auditoria_rf1_rf5_pki.json" \
  "$PY" -m tools.auditar_rf1_rf5_pki --total 300 --json "$LOGS/auditoria_rf1_rf5_pki.json"

prueba 'Ataques TLS controlados (+10 %)' "$EVIDENCIAS/ataques/tls_opcional.json" \
  "$PY" -m tools.ataque_opcional

if ! puerto_abierto "$PUERTO_GATEWAY" || ! puerto_abierto "$PUERTO_REGISTRO"; then
  aviso 'Los servicios no están en marcha; las pruebas 4 y 5 fallarán. Usa: bash laboratorio.sh arrancar'
fi
extra_tls=()
[[ "$SIN_VPN" == 1 ]] && extra_tls=(--sin-access-server)
prueba 'RS2: solo TLS 1.3 en los servicios en marcha' "$LOGS/tls_servicios.json" \
  "$PY" -m tools.comprobar_tls --json "$LOGS/tls_servicios.json" "${extra_tls[@]}"

prueba 'E2E real RF1 -> RF2 -> VPN -> RF4' "$LOGS/e2e_laboratorio.json" \
  "$PY" -m tools.prueba_e2e_laboratorio --json "$LOGS/e2e_laboratorio.json"

if [[ "$SIN_VPN" != 1 ]]; then
  prueba 'API REST de Access Server' '-' "$PY" -m tools.comprobar_access_server
fi

# ---------------------------------------------------------------- resumen
{
  printf 'BYODSEC · Resumen de pruebas · %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'Modo: %s\n\n' "$([[ "$SIN_VPN" == 1 ]] && echo 'sin VPN' || echo 'completo con Access Server')"
  for i in "${!NOMBRES[@]}"; do
    printf '  [%s] %-50s %s\n' "${ESTADOS[$i]}" "${NOMBRES[$i]}" "${FICHEROS[$i]}"
  done
  printf '\nPruebas manuales con el túnel real (no automatizables): ver README, sección "Pruebas manuales".\n'
} | tee "$LOGS/resumen_pruebas.txt"
fallos="$(grep -c '^\s*\[FAIL\]' "$LOGS/resumen_pruebas.txt")"
if [[ "$fallos" -gt 0 ]]; then
  printf "\n${R}[BYODSEC] %s prueba(s) con fallos.${N} Revisa los ficheros de evidencias indicados.\n" "$fallos"
  exit 1
fi
printf "\n${V}[BYODSEC] Todas las pruebas superadas.${N} Evidencias en evidencias/logs/\n"
