#!/usr/bin/env bash
# Paso 2: PKI corporativa (RS1), SQLite y 300 usuarios RF5 con certificado.
# Idempotente: nunca sobrescribe la CA, las cuentas ni las claves existentes.
source "$(dirname "${BASH_SOURCE[0]}")/comun.sh"
exigir_python

log 'Paso 2/5 · PKI corporativa BYODSEC'
if [[ -f pki/ca/ca.crt ]]; then
  ok 'CA existente (no se regenera)'
else
  "$PY" -m pki.scripts.pki crear-ca
  ok 'CA creada: pki/ca/ca.crt'
fi
if [[ -f pki/server/server.crt && -f pki/server/server.key ]]; then
  ok 'Certificado del servidor existente'
else
  "$PY" -m pki.scripts.pki emitir-servidor --nombre localhost
  ok 'Certificado del servidor emitido para localhost'
fi
openssl verify -x509_strict -purpose sslserver -verify_hostname localhost \
  -CAfile pki/ca/ca.crt pki/server/server.crt >/dev/null
ok 'Certificado del servidor verificado con OpenSSL estricto'

log 'Paso 2/5 · RF5: 300 usuarios (100 PDI, 100 PAS, 100 Investigadores)'
"$PY" -m src.rf5.cli precargar --total 300 >/dev/null
"$PY" -m src.rf5.cli certificados --limite 300 >/dev/null
"$PY" -m src.rf5.cli resumen
ok 'Contraseñas solo en pki/clients/rf5/credenciales.csv (local, excluido de Git)'
