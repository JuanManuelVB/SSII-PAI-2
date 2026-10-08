"""Pruebas del RF5: no requieren arrancar API ni alterar PKI del compañero."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.rf5 import gestion
from src.server import app as rf1


def rutas(tmp_path):
    return {
        "ruta_usuarios": tmp_path / "data" / "usuarios.json",
        "ruta_credenciales": tmp_path / "pki" / "rf5" / "credenciales.csv",
    }


def test_precarga_3_roles_hace_compatible_rf1_y_no_guarda_password_plana(tmp_path):
    parametros = rutas(tmp_path)
    resumen = gestion.precargar_usuarios(3, **parametros)
    usuarios = gestion.cargar_usuarios(parametros["ruta_usuarios"])
    credenciales = gestion._leer_credenciales(parametros["ruta_credenciales"])
    assert resumen["nuevos"] == 3
    assert {u["role"] for u in usuarios} == {"PDI", "PAS", "Investigador"}
    assert len(credenciales) == 3
    texto_usuarios = parametros["ruta_usuarios"].read_text(encoding="utf-8")
    for cuenta in credenciales:
        registro = next(u for u in usuarios if u["username"] == cuenta["username"])
        assert registro["status"] == "active"
        assert registro["password_hash"].startswith("scrypt$")
        assert rf1._verificar_contrasena(cuenta["password"], registro["password_hash"])
        assert not rf1._verificar_contrasena("incorrecta", registro["password_hash"])
        assert cuenta["password"] not in texto_usuarios
    assert parametros["ruta_credenciales"].stat().st_mode & 0o077 == 0



def test_consulta_de_perfil_activo_y_sin_datos_sensibles(tmp_path):
    parametros = rutas(tmp_path)
    gestion.precargar_usuarios(3, **parametros)
    resultado = gestion.consultar_perfil("rf5_pas_001", parametros["ruta_usuarios"])
    assert resultado == {
        "username": "rf5_pas_001", "role": "PAS", "device_id": "rf5-pas-001-dev01",
        "certificate_serial": "", "certificate_status": "pending",
    }
    assert gestion.consultar_perfil("nadie", parametros["ruta_usuarios"]) is None
    ruta = parametros["ruta_usuarios"]
    usuarios = gestion.cargar_usuarios(ruta)
    next(u for u in usuarios if u["username"] == "rf5_pas_001")["status"] = "revoked"
    ruta.write_text(json.dumps(usuarios), encoding="utf-8")
    assert gestion.consultar_perfil("rf5_pas_001", ruta) is None


def test_repetir_precarga_es_idempotente_y_respeta_usuarios_ajenos(tmp_path):
    parametros = rutas(tmp_path)
    ruta = parametros["ruta_usuarios"]
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ajeno = {"username": "usuario_de_rf1", "status": "active", "dato_externo": 42}
    ruta.write_text(json.dumps([ajeno]), encoding="utf-8")
    primera = gestion.precargar_usuarios(6, **parametros)
    originales = gestion.cargar_usuarios(ruta)
    segundo = gestion.precargar_usuarios(6, **parametros)
    assert primera["nuevos"] == 6
    assert segundo["nuevos"] == 0
    assert gestion.cargar_usuarios(ruta) == originales
    assert gestion.cargar_usuarios(ruta)[0] == ajeno
    assert gestion.resumen_usuarios(ruta)["total_rf5"] == 6


def test_300_usuarios_repartidos_y_mismo_nombre_no_duplicado(tmp_path, monkeypatch):
    # Se simula el hash solo en esta prueba masiva; la compatibilidad REAL
    # con scrypt se comprueba en test_precarga_3_roles_hace_compatible_rf1.
    monkeypatch.setattr(gestion, "_hash_password", lambda p: "hash-prueba-no-usar-en-produccion")
    parametros = rutas(tmp_path)
    assert gestion.precargar_usuarios(300, **parametros)["nuevos"] == 300
    conteo = gestion.resumen_usuarios(parametros["ruta_usuarios"])
    assert conteo["por_rol"] == {"PDI": 100, "PAS": 100, "Investigador": 100}
    assert conteo["total_rf5"] == 300
    assert gestion.precargar_usuarios(300, **parametros)["nuevos"] == 0


def test_json_corrupto_se_rechaza_y_no_se_pierde(tmp_path):
    parametros = rutas(tmp_path)
    ruta = parametros["ruta_usuarios"]
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text("NO ES JSON", encoding="utf-8")
    with pytest.raises(gestion.ErrorRF5, match="JSON inválido"):
        gestion.precargar_usuarios(3, **parametros)
    assert ruta.read_text(encoding="utf-8") == "NO ES JSON"


def test_cuenta_ajena_con_mismo_nombre_no_se_modifica(tmp_path):
    parametros = rutas(tmp_path)
    ruta = parametros["ruta_usuarios"]
    ruta.parent.mkdir(parents=True, exist_ok=True)
    preexistente = [{"username": "rf5_pdi_001", "status": "active", "origin": "RF1"}]
    ruta.write_text(json.dumps(preexistente), encoding="utf-8")
    with pytest.raises(gestion.ErrorRF5, match="Colisión"):
        gestion.precargar_usuarios(3, **parametros)
    assert json.loads(ruta.read_text(encoding="utf-8")) == preexistente


def _ca_temporal(tmp_path):
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA-Prueba-RF5")])
    ahora = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nombre).issuer_name(nombre).public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(days=1))
        .not_valid_after(ahora + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(clave, hashes.SHA256())
    )
    ruta_cert, ruta_clave = tmp_path / "ca.crt", tmp_path / "ca.key"
    ruta_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ruta_clave.write_bytes(clave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return ruta_cert, ruta_clave


def test_certificados_emitidos_y_reutilizados_sin_sustituir_claves(tmp_path):
    parametros = rutas(tmp_path)
    gestion.precargar_usuarios(3, **parametros)
    cert_ca, clave_ca = _ca_temporal(tmp_path)
    destino = tmp_path / "pki" / "rf5"
    args = dict(ruta_usuarios=parametros["ruta_usuarios"], directorio_destino=destino,
                ruta_ca_cert=cert_ca, ruta_ca_key=clave_ca)
    resultado = gestion.emitir_certificados(**args)
    assert resultado == {"emitidos": 3, "reutilizados": 0, "total_procesados": 3}
    certificado = destino / "rf5_pdi_001.crt"
    clave = destino / "rf5_pdi_001.key"
    previo = clave.read_bytes()
    x509.load_pem_x509_certificate(certificado.read_bytes())
    assert clave.stat().st_mode & 0o077 == 0
    assert gestion.resumen_usuarios(parametros["ruta_usuarios"])["certificados_emitidos"] == 3
    assert gestion.emitir_certificados(**args) == {
        "emitidos": 0, "reutilizados": 3, "total_procesados": 3,
    }
    assert clave.read_bytes() == previo


def test_no_emite_una_ca_inexistente_sin_alterar_usuarios(tmp_path):
    parametros = rutas(tmp_path)
    gestion.precargar_usuarios(3, **parametros)
    antes = parametros["ruta_usuarios"].read_bytes()
    with pytest.raises(gestion.ErrorRF5, match="Falta la CA"):
        gestion.emitir_certificados(
            ruta_usuarios=parametros["ruta_usuarios"],
            directorio_destino=tmp_path / "clientes",
            ruta_ca_cert=tmp_path / "ca-no-existe.crt",
            ruta_ca_key=tmp_path / "ca-no-existe.key",
        )
    assert parametros["ruta_usuarios"].read_bytes() == antes
