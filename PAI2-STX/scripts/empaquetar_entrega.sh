#!/usr/bin/env bash
# Genera el ZIP de entrega SIN secretos ni estado local:
# excluye claves, certificados emitidos, SQLite, CSV de contraseñas, perfiles
# .ovpn, entornos virtuales, cachés, logs JSONL de auditoría y capturas .pcap.
# Uso: bash laboratorio.sh entregar          -> ../PAI2-STX.zip
#      bash scripts/empaquetar_entrega.sh RUTA.zip [--con-pcap]
source "$(dirname "${BASH_SOURCE[0]}")/comun.sh"

destino="${1:-$(dirname "$ROOT")/PAI2-STX.zip}"
con_pcap=0
[[ "${2:-}" == --con-pcap ]] && con_pcap=1

log "Empaquetando la entrega en $destino"
python3 - "$ROOT" "$destino" "$con_pcap" <<'PY'
import fnmatch
import pathlib
import re
import sys
import zipfile

raiz, destino, con_pcap = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3] == '1'
DIRECTORIOS_EXCLUIDOS = {'.git', '.venv', '.venv-wsl', '__pycache__', '.pytest_cache'}
EXCLUIDOS = [
    'data/*.sqlite3*', 'pki/ca/*', 'pki/server/*', 'pki/clients/*',
    '*.key', '*.csr', '*.p12', '*.ovpn', '.env', '.env.*', 'credenciales.csv',
    'evidencias/logs/*.jsonl', '_respaldo*', '*.zip', '*.tgz', '*.tar', '*.pyc',
]
if not con_pcap:
    EXCLUIDOS.append('evidencias/pcap/*.pcap*')

incluidos = []
for ruta in sorted(raiz.rglob('*')):
    relativa = ruta.relative_to(raiz)
    if not ruta.is_file() or DIRECTORIOS_EXCLUIDOS & set(relativa.parts):
        continue
    texto = relativa.as_posix()
    if ruta.name != '.gitkeep' and any(fnmatch.fnmatch(texto, p) or fnmatch.fnmatch(ruta.name, p)
                                       for p in EXCLUIDOS):
        continue
    incluidos.append((ruta, texto))

destino.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(destino, 'w', zipfile.ZIP_DEFLATED) as zf:
    for ruta, texto in incluidos:
        zf.write(ruta, f'PAI2-STX/{texto}')

# Comprobación final: nada con aspecto de secreto dentro del ZIP
# (una clave PEM real: cabecera seguida de contenido base64).
CLAVE_PEM = re.compile(rb'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{40}')
with zipfile.ZipFile(destino) as zf:
    nombres = zf.namelist()
    prohibidos = [n for n in nombres if n.endswith(('.key', '.ovpn', '.sqlite3', 'credenciales.csv'))]
    prohibidos += [n for n in nombres if CLAVE_PEM.search(zf.read(n))]
if prohibidos:
    destino.unlink()
    raise SystemExit('ZIP descartado: contiene material sensible: ' + ', '.join(prohibidos))
print(f'  {len(nombres)} ficheros, {destino.stat().st_size // 1024} KiB, sin claves ni bases de datos')
PY
ok "Entrega lista: $destino"
