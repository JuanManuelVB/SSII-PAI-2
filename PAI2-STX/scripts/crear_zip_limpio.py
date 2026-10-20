"""ZIP del código del camino A. Por diseño, NUNCA incluye credenciales ni PKI real."""
from pathlib import Path
import sys,zipfile,fnmatch
ROOT=Path(__file__).resolve().parents[1]
DEST=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else ROOT.parent/'PAI2-STX_CAMINO_A_LIMPIO.zip'
SKIP_DIRS={'.git','.venv','.venv-wsl','__pycache__','.pytest_cache','backups','node_modules'}
SKIP_NAMES={'credenciales.csv','.env','revoked.json'}
SKIP_EXT={'.key','.pem','.p12','.pfx','.ovpn','.sqlite3','.db','.pcap','.pcapng','.pyc','.log','.zip'}
with zipfile.ZipFile(DEST,'w',zipfile.ZIP_DEFLATED,compresslevel=8) as z:
 for p in sorted(ROOT.rglob('*')):
  if not p.is_file() or SKIP_DIRS.intersection(p.relative_to(ROOT).parts) or p.resolve()==DEST:continue
  rel=p.relative_to(ROOT)
  if p.name in SKIP_NAMES or p.suffix in SKIP_EXT or p.name.endswith(('.sqlite3-wal','.sqlite3-shm')):continue
  if rel.parts[0]=='pki' and len(rel.parts)>1 and rel.parts[1] in ('ca','clients','server') and p.name!='.gitkeep':continue
  if rel.parts[0] in ('data','evidencias','bench') and p.name!='.gitkeep':continue
  if p.name.startswith('_respaldo'):continue
  z.write(p,'PAI2-STX/'+str(rel).replace('\\','/'))
print('ZIP listo:',DEST)
