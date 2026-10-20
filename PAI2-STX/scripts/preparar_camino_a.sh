#!/usr/bin/env bash
# Preparación segura del laboratorio. Nunca reemplaza el material privado existente.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [ ! -x .venv-wsl/bin/python ]; then
    python3 -m venv .venv-wsl
fi
.venv-wsl/bin/python -m pip install -r requirements.txt
if [ -f data/rf1.sqlite3 ] && { [ ! -f pki/ca/ca.crt ] || [ ! -f pki/ca/ca.key ]; }; then
    echo 'ERROR: existe una base de datos, pero falta la CA original.' >&2
    echo 'Recupera pki/ca/ca.crt y pki/ca/ca.key de TU instalación anterior, no generes otra.' >&2
    exit 2
fi
if [ -f pki/ca/ca.crt ] && [ ! -f pki/ca/ca.key ] || [ ! -f pki/ca/ca.crt ] && [ -f pki/ca/ca.key ]; then
    echo 'ERROR: la CA está incompleta. Recupera ambos archivos del mismo laboratorio.' >&2
    exit 2
fi
if [ ! -f pki/ca/ca.crt ]; then
    .venv-wsl/bin/python -m pki.scripts.pki crear-ca
fi
if [ ! -f pki/server/server.crt ] && [ ! -f pki/server/server.key ]; then
    .venv-wsl/bin/python -m pki.scripts.pki emitir-servidor --nombre localhost
elif [ ! -f pki/server/server.crt ] || [ ! -f pki/server/server.key ]; then
    echo 'ERROR: falta un componente del par de claves del servidor.' >&2
    exit 2
fi
.venv-wsl/bin/python -m src.rf5.cli precargar --total 300
.venv-wsl/bin/python -m src.rf5.cli certificados --limite 300
.venv-wsl/bin/python -m src.rf5.cli resumen
printf '\n[OK] Camino A preparado; claves y credenciales guardadas SOLO en este equipo.\n'
