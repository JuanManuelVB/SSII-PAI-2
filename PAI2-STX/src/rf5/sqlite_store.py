"""RF5: almacenamiento SQLite compartido con RF1, sin modificar RF1.

Los hashes scrypt se importan sin volver a calcularlos. El JSON anterior es
exclusivamente una fuente de migración, no se consulta durante la ejecución.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .gestion import (
    DIRECTORIO_PRIVADO, RUTA_CA_CERT, RUTA_CA_KEY, RUTA_CREDENCIALES,
    RUTA_USUARIOS, ErrorRF5, PERFILES, _cargar_ca, _certificado_valido,
    _crear_certificado, _csv_credenciales, _escribir_atomico, _hash_password,
    _leer_credenciales, cargar_usuarios, reparto_roles,
)

RAIZ = Path(__file__).resolve().parents[2]
RUTA_SQLITE = RAIZ / 'data' / 'rf1.sqlite3'
ROL_BD = {'PDI': 'PDI', 'PAS': 'PAS', 'Investigador': 'INVESTIGADOR'}
ROL_RF5 = {valor: clave for clave, valor in ROL_BD.items()}


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def abrir_db(ruta: Path = RUTA_SQLITE):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(ruta, timeout=15)
    conexion.row_factory = sqlite3.Row
    try:
        conexion.execute('PRAGMA foreign_keys=ON')
        yield conexion
    finally:
        conexion.close()


def iniciar_esquema(conexion: sqlite3.Connection) -> None:
    """Las dos primeras tablas tienen EXACTAMENTE el esquema de RF1.

    CREATE IF NOT EXISTS no altera ni borra usuarios/dispositivos anteriores.
    """
    conexion.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('PDI', 'PAS', 'INVESTIGADOR')),
            status TEXT NOT NULL CHECK(status IN ('active', 'blocked', 'revoked')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_pairings (
            device_id TEXT PRIMARY KEY,
            username TEXT NOT NULL REFERENCES users(username),
            public_key_fingerprint TEXT NOT NULL UNIQUE,
            certificate_serial TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active', 'revoked'))
        );
        CREATE TABLE IF NOT EXISTS rf5_accounts (
            username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE RESTRICT,
            planned_device_id TEXT NOT NULL UNIQUE,
            certificate_status TEXT NOT NULL DEFAULT 'pending'
                CHECK(certificate_status IN ('pending', 'issued')),
            certificate_path TEXT,
            certificate_serial TEXT
        );
    ''')
    conexion.commit()


def _verificar_hash(valor: object) -> None:
    if not isinstance(valor, str):
        raise ErrorRF5('Registro RF5 sin hash de contraseña')
    partes = valor.split('$')
    if len(partes) != 3 or partes[0] != 'scrypt':
        raise ErrorRF5('Formato de hash distinto al utilizado por RF1')
    try:
        sal, resumen = bytes.fromhex(partes[1]), bytes.fromhex(partes[2])
    except ValueError as exc:
        raise ErrorRF5('Hash de contraseña con codificación no válida') from exc
    if len(sal) != 16 or len(resumen) != 64:
        raise ErrorRF5('Hash scrypt de longitud incompatible con RF1')


def _validar_cuenta(u: dict) -> tuple[str, str, str, str, str]:
    if u.get('origin') != 'RF5':
        raise ErrorRF5('El JSON contiene cuentas ajenas al RF5; revisa la migración manualmente')
    nombre, rol, estado, disp = (u.get('username'), u.get('role'), u.get('status'), u.get('device_id'))
    if not isinstance(nombre, str) or not nombre or len(nombre) > 64:
        raise ErrorRF5('Nombre de usuario RF5 inválido')
    if rol not in ROL_BD or estado not in ('active', 'blocked', 'revoked'):
        raise ErrorRF5(f'Rol o estado inválido para {nombre}')
    if not isinstance(disp, str) or not disp or len(disp) > 128:
        raise ErrorRF5(f'Dispositivo de prueba inválido para {nombre}')
    _verificar_hash(u.get('password_hash'))
    return nombre, ROL_BD[rol], estado, disp, u['password_hash']


def importar_json(*, ruta_json: Path = RUTA_USUARIOS, ruta_db: Path = RUTA_SQLITE) -> dict:
    """Migra una vez o se puede repetir; nunca sobrescribe datos existentes.

    Ante cualquier colisión incompatible, revierte todos los inserts del lote.
    No registra certificados como válidos si aún no están vinculados en SQLite.
    """
    if not ruta_json.is_file():
        raise ErrorRF5(f'No existe el JSON original: {ruta_json}')
    usuarios = cargar_usuarios(ruta_json)
    preparados = [_validar_cuenta(u) for u in usuarios]
    if len({x[3] for x in preparados}) != len(preparados):
        raise ErrorRF5('Dos cuentas RF5 contienen el mismo identificador de dispositivo')
    # Copia en caliente con la API de SQLite: válida incluso si la BD usa WAL.
    # Solo el fichero SQLite se respalda; nunca se modifica el JSON origen.
    ruta_respaldo = None
    if ruta_db.exists():
        carpeta = ruta_db.parent / 'backups'
        carpeta.mkdir(parents=True, exist_ok=True)
        ruta_respaldo = carpeta / f'{ruta_db.stem}-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%f}.backup.sqlite3'
        with sqlite3.connect(ruta_db) as origen, sqlite3.connect(ruta_respaldo) as copia:
            origen.backup(copia)
    nuevos = 0
    existentes = 0
    with abrir_db(ruta_db) as db:
        iniciar_esquema(db)
        try:
            db.execute('BEGIN IMMEDIATE')
            for nombre, rol, estado, disp, hash_pw in preparados:
                anterior = db.execute('SELECT * FROM users WHERE username=?', (nombre,)).fetchone()
                if anterior:
                    if (anterior['role'], anterior['status'], anterior['password_hash']) != (rol, estado, hash_pw):
                        raise ErrorRF5(f'Conflicto con usuario SQLite {nombre}; no se sobrescribe')
                    existentes += 1
                else:
                    ahora = _ahora()
                    db.execute('''INSERT INTO users
                        (username, password_hash, role, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)''', (nombre, hash_pw, rol, estado, ahora, ahora))
                    nuevos += 1
                vinculo = db.execute('SELECT * FROM rf5_accounts WHERE username=?', (nombre,)).fetchone()
                if vinculo:
                    if vinculo['planned_device_id'] != disp:
                        raise ErrorRF5(f'Dispositivo distinto para {nombre}; no se modifica')
                else:
                    # Importar cuenta no implica que su certificado haya superado mTLS.
                    db.execute('INSERT INTO rf5_accounts(username, planned_device_id) VALUES (?, ?)',
                               (nombre, disp))
            db.commit()
        except (sqlite3.Error, ErrorRF5):
            db.rollback()
            raise
    return {'cuentas_json': len(preparados), 'insertadas': nuevos,
            'ya_existentes': existentes, 'sqlite': str(ruta_db),
            'respaldo_previo': str(ruta_respaldo) if ruta_respaldo else None}


def precargar_sqlite(*, total: int = 300, ruta_db: Path = RUTA_SQLITE,
                      ruta_credenciales: Path = RUTA_CREDENCIALES) -> dict:
    """En adelante RF5 crea cuentas directamente en SQLite, NO en JSON.

    Para nuevas cuentas, escribe las contraseñas de laboratorio en el CSV
    local privado existente, nunca en SQLite en texto claro.
    """
    reparto = reparto_roles(total)
    creados = []
    with abrir_db(ruta_db) as db:
        iniciar_esquema(db)
        secretos_anteriores = _leer_credenciales(ruta_credenciales)
        por_nombre = {u['username'] for u in secretos_anteriores}
        try:
            db.execute('BEGIN IMMEDIATE')
            for rol, prefijo in PERFILES.items():
                for num in range(1, reparto[rol] + 1):
                    nombre = f'rf5_{prefijo}_{num:03d}'
                    disp = f'rf5-{prefijo}-{num:03d}-dev01'
                    usuario = db.execute('SELECT * FROM users WHERE username=?', (nombre,)).fetchone()
                    cuenta = db.execute('SELECT * FROM rf5_accounts WHERE username=?', (nombre,)).fetchone()
                    if usuario or cuenta:
                        if (not usuario or not cuenta or usuario['role'] != ROL_BD[rol]
                                or cuenta['planned_device_id'] != disp):
                            raise ErrorRF5(f'Colisión con cuenta ajena o incompleta: {nombre}')
                        continue
                    if nombre in por_nombre:
                        raise ErrorRF5(f'Credenciales existentes sin cuenta SQLite: {nombre}')
                    secreto = secrets.token_urlsafe(24)
                    ahora = _ahora()
                    db.execute('''INSERT INTO users
                        (username, password_hash, role, status, created_at, updated_at)
                        VALUES (?, ?, ?, 'active', ?, ?)''', (nombre, _hash_password(secreto), ROL_BD[rol], ahora, ahora))
                    db.execute('INSERT INTO rf5_accounts (username, planned_device_id) VALUES (?, ?)',
                               (nombre, disp))
                    creados.append({'username': nombre, 'password': secreto,
                                   'role': rol, 'device_id': disp})
            if creados:
                # Guardar secretos ANTES de confirmar nuevos registros en la BD.
                _escribir_atomico(ruta_credenciales,
                    _csv_credenciales(secretos_anteriores + creados), privado=True)
            db.commit()
        except (sqlite3.Error, OSError, ErrorRF5):
            db.rollback()
            raise
    return {'nuevos': len(creados), 'total_solicitado': total, 'sqlite': str(ruta_db),
            'credenciales_laboratorio': str(ruta_credenciales)}


def resumen_sqlite(*, ruta_db: Path = RUTA_SQLITE) -> dict:
    with abrir_db(ruta_db) as db:
        iniciar_esquema(db)
        roles = Counter()
        for fila in db.execute('''SELECT users.role, count(*) as cantidad FROM users
            JOIN rf5_accounts rf5 ON rf5.username=users.username GROUP BY users.role'''):
            roles[ROL_RF5[fila['role']]] = fila['cantidad']
        return {
            'usuarios_totales': db.execute('SELECT count(*) FROM users').fetchone()[0],
            'usuarios_rf5': db.execute('SELECT count(*) FROM rf5_accounts').fetchone()[0],
            'por_rol_rf5': dict(roles),
            'certificados_vinculados': db.execute('''SELECT count(*) FROM rf5_accounts
                WHERE certificate_status='issued' ''').fetchone()[0],
            'dispositivos_registrados': db.execute('SELECT count(*) FROM device_pairings').fetchone()[0],
            'sqlite': str(ruta_db),
        }


def consultar_perfil_sqlite(nombre: str, *, ruta_db: Path = RUTA_SQLITE) -> dict | None:
    with abrir_db(ruta_db) as db:
        iniciar_esquema(db)
        u = db.execute('''SELECT u.username,u.role,u.status, r.planned_device_id,
            r.certificate_status,r.certificate_serial,r.certificate_path FROM users u
            JOIN rf5_accounts r ON r.username=u.username WHERE u.username=?''', (nombre,)).fetchone()
        if u is None or u['status'] != 'active':
            return None
        d = dict(u)
        d['role'] = ROL_RF5[d['role']]
        d.pop('status')
        return d


def asociar_certificados(*, ruta_db: Path = RUTA_SQLITE,
                          directorio: Path = DIRECTORIO_PRIVADO,
                          ruta_ca_cert: Path = RUTA_CA_CERT,
                          ruta_ca_key: Path = RUTA_CA_KEY,
                          limite: int | None = None) -> dict:
    """Certificados cliente del laboratorio: genera/reutiliza y enlaza en SQLite.

    No sustituye pares existentes. No modifica la CA de RF1. La clave privada
    nunca se guarda en SQLite. El handshake mTLS real corresponde a RF2.
    """
    if limite is not None and limite < 1:
        raise ErrorRF5('--limite debe ser mayor que cero')
    ca, clave_ca = _cargar_ca(ruta_ca_cert, ruta_ca_key)
    vinculados = reutilizados = 0
    with abrir_db(ruta_db) as db:
        iniciar_esquema(db)
        cuentas = db.execute('''SELECT u.username, u.status, r.planned_device_id,
            r.certificate_status, r.certificate_serial FROM rf5_accounts r
            JOIN users u ON u.username=r.username ORDER BY u.username''').fetchall()
        if not cuentas:
            raise ErrorRF5('No hay cuentas RF5 en SQLite; ejecuta primero migrar o precargar')
        for cuenta in cuentas[:limite]:
            usuario, dispositivo = cuenta['username'], cuenta['planned_device_id']
            if cuenta['status'] != 'active':
                continue
            archivo_key = directorio / f'{usuario}.key'
            archivo_crt = directorio / f'{usuario}.crt'
            if archivo_key.exists() != archivo_crt.exists():
                raise ErrorRF5(f'Certificado/clave incompletos de {usuario}; se requiere revisión manual')
            if archivo_key.exists():
                certificado = x509.load_pem_x509_certificate(archivo_crt.read_bytes())
                clave = serialization.load_pem_private_key(archivo_key.read_bytes(), password=None)
                if not _certificado_valido(certificado, clave, ca, usuario, dispositivo):
                    raise ErrorRF5(f'Certificado existente inválido para {usuario}; no se sobrescribe')
                reutilizados += 1
            else:
                clave, certificado = _crear_certificado(usuario, dispositivo, ca, clave_ca)
                _escribir_atomico(archivo_key, clave.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()).decode('ascii'), privado=True)
                _escribir_atomico(archivo_crt, certificado.public_bytes(
                    serialization.Encoding.PEM).decode('ascii'), privado=False)
            huella = hashlib.sha256(certificado.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            serie = str(certificado.serial_number)
            existente = db.execute('SELECT * FROM device_pairings WHERE device_id=?', (dispositivo,)).fetchone()
            if existente and (existente['username'], existente['public_key_fingerprint'],
                              existente['certificate_serial'], existente['status']) != (usuario, huella, serie, 'active'):
                raise ErrorRF5(f'Emparejamiento distinto para {dispositivo}; intervención manual necesaria')
            try:
                with db:
                    if not existente:
                        db.execute('''INSERT INTO device_pairings
                            (device_id, username, public_key_fingerprint, certificate_serial, created_at, status)
                            VALUES (?, ?, ?, ?, ?, 'active')''', (dispositivo, usuario, huella, serie, _ahora()))
                    db.execute('''UPDATE rf5_accounts SET certificate_status='issued',
                        certificate_serial=?, certificate_path=? WHERE username=?''',
                        (serie, f'pki/clients/rf5/{usuario}.crt', usuario))
            except sqlite3.IntegrityError as exc:
                raise ErrorRF5(f'Conflicto de certificado o clave para {usuario}') from exc
            vinculados += 1
    return {'vinculados': vinculados, 'certificados_reutilizados': reutilizados,
            'sqlite': str(ruta_db)}
