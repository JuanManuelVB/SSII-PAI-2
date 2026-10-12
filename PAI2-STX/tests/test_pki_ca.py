"""Pruebas PKI sin escribir certificados ni claves en el proyecto real."""
import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from src.pki_tools.cli import iniciar_ca, emitir_servidor, verificar, ErrorPKI
from src.pki_tools.prueba_mtls import probar_mtls
from src.rf5.sqlite_store import precargar_sqlite, asociar_certificados, resumen_sqlite


def test_ca_y_certificado_servidor_san_tls13(tmp_path):
    ca_crt, ca_key = iniciar_ca(tmp_path)
    assert ca_crt.is_file() and ca_key.is_file()
    crt, key = emitir_servidor(tmp_path, dns=('us-proyecto.local',), ip=('192.0.2.10',))
    cert = x509.load_pem_x509_certificate(crt.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert 'localhost' in san.get_values_for_type(x509.DNSName)
    assert 'us-proyecto.local' in san.get_values_for_type(x509.DNSName)
    assert ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert verificar(tmp_path)['servidor'] == 'válido'
    with pytest.raises(ErrorPKI, match='No se sobreescribe'):
        emitir_servidor(tmp_path)
    with pytest.raises(ErrorPKI, match='No regenerarlos'):
        iniciar_ca(tmp_path)
    assert key.is_file()


def test_ca_compatible_con_rf5_y_mtls_real(tmp_path):
    iniciar_ca(tmp_path)
    emitir_servidor(tmp_path)
    db = tmp_path / 'data' / 'rf1.sqlite3'
    usuarios = tmp_path / 'pki' / 'clients' / 'rf5'
    precargar_sqlite(total=3, ruta_db=db, ruta_credenciales=usuarios / 'credenciales.csv')
    resultado = asociar_certificados(
        ruta_db=db, directorio=usuarios,
        ruta_ca_cert=tmp_path / 'pki' / 'ca' / 'ca.crt',
        ruta_ca_key=tmp_path / 'pki' / 'ca' / 'ca.key',
        limite=3,
    )
    assert resultado['vinculados'] == 3
    assert resumen_sqlite(ruta_db=db)['dispositivos_registrados'] == 3
    assert probar_mtls(tmp_path, usuario='rf5_inv_001') is True
    assert probar_mtls(tmp_path, sin_certificado=True) is True


def test_archivo_ca_incompleto_no_regenera(tmp_path):
    ruta = tmp_path / 'pki' / 'ca'
    ruta.mkdir(parents=True)
    (ruta / 'ca.crt').write_text('certificado incompleto')
    with pytest.raises(ErrorPKI, match='Ya hay ficheros de CA'):
        iniciar_ca(tmp_path)
    assert not (ruta / 'ca.key').exists()


def test_certificado_servidor_no_emite_sin_ca(tmp_path):
    with pytest.raises(ErrorPKI, match='ejecuta primero iniciar-ca'):
        emitir_servidor(tmp_path)
