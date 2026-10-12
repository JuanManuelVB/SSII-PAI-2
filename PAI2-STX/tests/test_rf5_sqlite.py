"""Integración RF1/RF5: tests con bases temporales; no usan datos reales."""

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from src.rf5 import sqlite_store as store
from src.rf5.gestion import ErrorRF5, _hash_password
from src.server import app as rf1


def usuario(nombre, rol='PDI', estado='active', disp=None, password='clave-segura-de-prueba'):
    return {
        'username': nombre, 'role': rol, 'status': estado,
        'device_id': disp or nombre + '-device', 'origin': 'RF5',
        'password_hash': _hash_password(password), 'certificate_status': 'pending',
    }


def guardar(ruta: Path, cuentas):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(cuentas), encoding='utf-8')


def test_migrar_importa_roles_y_rf1_los_reconoce(tmp_path):
    ruta_db, ruta_json = tmp_path / 'db.sqlite3', tmp_path / 'usuarios.json'
    cuentas = [usuario('pdi1'), usuario('pas1', 'PAS'), usuario('inv1', 'Investigador')]
    guardar(ruta_json, cuentas)
    out = store.importar_json(ruta_json=ruta_json, ruta_db=ruta_db)
    assert out['insertadas'] == 3
    with patch.object(rf1, 'RUTA_BASE_DATOS', ruta_db):
        para_rf1 = rf1._cargar_usuario('inv1')
        assert para_rf1['role'] == 'INVESTIGADOR'
        assert rf1._verificar_contrasena('clave-segura-de-prueba', para_rf1['password_hash'])
    resumen = store.resumen_sqlite(ruta_db=ruta_db)
    assert resumen['usuarios_rf5'] == 3
    assert resumen['usuarios_totales'] == 3
    assert resumen['dispositivos_registrados'] == 0  # pendiente de certificado
    assert resumen['certificados_vinculados'] == 0
    assert store.consultar_perfil_sqlite('inv1', ruta_db=ruta_db)['role'] == 'Investigador'


def test_migracion_repetida_no_duplica(tmp_path):
    ruta_db, ruta_json = tmp_path / 'db.sqlite3', tmp_path / 'usuarios.json'
    guardar(ruta_json, [usuario('a')])
    store.importar_json(ruta_json=ruta_json, ruta_db=ruta_db)
    segunda = store.importar_json(ruta_json=ruta_json, ruta_db=ruta_db)
    assert segunda['insertadas'] == 0 and segunda['ya_existentes'] == 1
    assert store.resumen_sqlite(ruta_db=ruta_db)['usuarios_rf5'] == 1


def test_cuenta_manual_rf1_se_preserva(tmp_path):
    ruta_db, ruta_json = tmp_path / 'db.sqlite3', tmp_path / 'usuarios.json'
    with store.abrir_db(ruta_db) as db:
        store.iniciar_esquema(db)
        db.execute("INSERT INTO users(username,password_hash,role,status,created_at,updated_at) VALUES(?, ?, 'PAS','blocked','x','x')", ('manual', _hash_password('otra clave')))
        db.commit()
    guardar(ruta_json, [usuario('rf5_1')])
    store.importar_json(ruta_json=ruta_json, ruta_db=ruta_db)
    with store.abrir_db(ruta_db) as db:
        assert db.execute("SELECT status FROM users WHERE username='manual'").fetchone()[0] == 'blocked'
    assert store.resumen_sqlite(ruta_db=ruta_db)['usuarios_totales'] == 2


def test_conflicto_revierte_lote_y_no_modifica_datos(tmp_path):
    ruta_db, ruta_json = tmp_path / 'db.sqlite3', tmp_path / 'usuarios.json'
    cuentas = [usuario('primero'), usuario('conflicto')]
    guardar(ruta_json, cuentas)
    with store.abrir_db(ruta_db) as db:
        store.iniciar_esquema(db)
        db.execute("INSERT INTO users(username,password_hash,role,status,created_at,updated_at) VALUES(?, ?, 'PAS','blocked','x','x')", ('conflicto', _hash_password('distinta')))
        db.commit()
    with pytest.raises(ErrorRF5, match='Conflicto'):
        store.importar_json(ruta_json=ruta_json, ruta_db=ruta_db)
    with store.abrir_db(ruta_db) as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM rf5_accounts").fetchone()[0] == 0


def test_precarga_sqlite_no_usa_json_y_no_duplica(tmp_path):
    ruta_db = tmp_path / 'db.sqlite3'
    credenciales = tmp_path / 'privado' / 'credenciales.csv'
    resultado = store.precargar_sqlite(total=6, ruta_db=ruta_db, ruta_credenciales=credenciales)
    assert resultado['nuevos'] == 6
    assert store.precargar_sqlite(total=6, ruta_db=ruta_db, ruta_credenciales=credenciales)['nuevos'] == 0
    assert store.resumen_sqlite(ruta_db=ruta_db)['por_rol_rf5'] == {'PDI': 2, 'PAS': 2, 'Investigador': 2}
    assert not (tmp_path / 'usuarios.json').exists()
    with patch.object(rf1, 'RUTA_BASE_DATOS', ruta_db):
        assert rf1._cargar_usuario('rf5_pdi_001') is not None
    assert credenciales.is_file()


def test_certificados_exigen_ca_y_no_generan_una_falsa(tmp_path):
    ruta_db = tmp_path / 'db.sqlite3'
    store.precargar_sqlite(total=3, ruta_db=ruta_db, ruta_credenciales=tmp_path / 'cred.csv')
    with pytest.raises(ErrorRF5, match='Falta la CA'):
        store.asociar_certificados(ruta_db=ruta_db, ruta_ca_cert=tmp_path / 'none.crt', ruta_ca_key=tmp_path / 'none.key')
    assert store.resumen_sqlite(ruta_db=ruta_db)['certificados_vinculados'] == 0


def test_json_ajeno_o_erroneo_no_se_importa_parcial(tmp_path):
    ruta_db, ruta_json = tmp_path / 'db.sqlite3', tmp_path / 'usuarios.json'
    cuentas = [usuario('ok'), {**usuario('otro'), 'origin': 'RF1'}]
    guardar(ruta_json, cuentas)
    with pytest.raises(ErrorRF5, match='ajenas'):
        store.importar_json(ruta_json=ruta_json, ruta_db=ruta_db)
    assert not ruta_db.exists()


def test_certificados_se_vinculan_a_device_pairings_y_se_reutilizan(tmp_path):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CA-RF5-Test')])
    ahora = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nombre).issuer_name(nombre)
            .public_key(clave.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(ahora - timedelta(days=1)).not_valid_after(ahora + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(clave, hashes.SHA256()))
    ca_cert, ca_key = tmp_path / 'ca.crt', tmp_path / 'ca.key'
    ca_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ca_key.write_bytes(clave.private_bytes(serialization.Encoding.PEM,
                       serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    db, destino = tmp_path / 'db.sqlite3', tmp_path / 'clientes'
    store.precargar_sqlite(total=3, ruta_db=db, ruta_credenciales=tmp_path / 'private.csv')
    parametros = {'ruta_db': db, 'directorio': destino,
                  'ruta_ca_cert': ca_cert, 'ruta_ca_key': ca_key}
    primero = store.asociar_certificados(**parametros)
    assert primero['vinculados'] == 3 and primero['certificados_reutilizados'] == 0
    antigua = (destino / 'rf5_pdi_001.key').read_bytes()
    segundo = store.asociar_certificados(**parametros)
    assert segundo['vinculados'] == 3 and segundo['certificados_reutilizados'] == 3
    assert (destino / 'rf5_pdi_001.key').read_bytes() == antigua
    stats = store.resumen_sqlite(ruta_db=db)
    assert stats['certificados_vinculados'] == 3
    assert stats['dispositivos_registrados'] == 3
    with store.abrir_db(db) as conexion:
        assert conexion.execute('SELECT count(*) FROM device_pairings').fetchone()[0] == 3
