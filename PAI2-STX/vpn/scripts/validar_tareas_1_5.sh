#!/usr/bin/env bash
# QA reproducible de las 5 primeras tareas, sin claves privadas ni servidor AS.
set -euo pipefail
cd "$(dirname "$0")/../.."
python -m pytest -q \
  tests/test_tareas_1_5.py \
  tests/test_vpn_rest_as.py \
  tests/test_vpn_rest_integration.py \
  tests/test_interfaz_consola.py \
  tests/test_certificado_identidad.py \
  tests/test_mtls.py \
  tests/test_pki.py
printf '\nPruebas de codigo/PKI terminadas.\n'
printf 'Auditoria real de certificados RF5 (no modifica datos):\n'
python -m tools.auditar_rf1_rf5_pki --total 300 --json evidencias/logs/rf1_rf5_pki_auditoria.json
