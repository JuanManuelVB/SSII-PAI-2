"""Pruebas de RF2: login con certificado mTLS + usuario/contraseña."""

from __future__ import annotations

import queue
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pki.scripts import pki
from src.common.base_datos import conectar_base_datos, inicializar_base_datos
from src.common.seguridad import crear_hash_contrasena
from src.rf5 import gestion
from src.server import autenticacion
from src.server.autenticacion import (
    MENSAJE_PUBLICO,
    CertificadoDeOtroUsuario,
    CertificadoNoEmparejado,
    ContrasenaIncorrecta,
    DispositivoRevocado,
    ErrorAutenticacion,
    HuellaInvalida,
    UsuarioInactivo,
    UsuarioInexistente,
    autenticar_usuario,
)
from src.server.identidad_certificado import huella_desde_conexion_tls
from src.server.tls import crear_contexto_tls_servidor, obtener_huella_clave_certificado

CONTRASENA = "contrasena-login-rf2"


def _huella_de_fichero(ruta_certificado) -> str:
    """Calcula la huella con la función pública de la capa TLS."""
    certificado = x509.load_pem_x509_certificate(ruta_certificado.read_bytes())
    return obtener_huella_clave_certificado(
        certificado.public_bytes(serialization.Encoding.DER)
    )


class Entorno:
    """CA, base SQLite y usuarios manuales temporales para cada prueba."""

    def __init__(self, raiz):
        self.raiz = raiz
        self.db = raiz / "data" / "rf1.sqlite3"
        pki.crear_ca(raiz)
        inicializar_base_datos(self.db)

    def certificado(self, nombre: str):
        pki.emitir_cliente(self.raiz, nombre)
        return self.raiz / "pki" / "clients" / nombre / f"{nombre}.crt"

    def usuario(self, username: str, *, status: str = "active") -> None:
        with conectar_base_datos(self.db) as conexion:
            conexion.execute(
                """
                INSERT INTO users
                (username, password_hash, role, status, origin, created_at, updated_at)
                VALUES (?, ?, 'PDI', ?, 'MANUAL', 't', 't')
                """,
                (username, crear_hash_contrasena(CONTRASENA), status),
            )

    def emparejar(self, username: str, device_id: str, ruta_certificado) -> str:
        huella = _huella_de_fichero(ruta_certificado)
        serie = str(x509.load_pem_x509_certificate(ruta_certificado.read_bytes()).serial_number)
        with conectar_base_datos(self.db) as conexion:
            conexion.execute(
                """
                INSERT INTO device_pairings
                (device_id, username, public_key_fingerprint, certificate_serial,
                 certificate_path, created_at, status)
                VALUES (?, ?, ?, ?, ?, 't', 'active')
                """,
                (device_id, username, huella, serie, str(ruta_certificado)),
            )
        return huella


@pytest.fixture
def entorno(tmp_path):
    """Usuario manual 'pdi001' con su dispositivo 'byod-001' emparejado."""
    datos = Entorno(tmp_path)
    datos.usuario("pdi001")
    datos.huella = datos.emparejar("pdi001", "byod-001", datos.certificado("byod-001"))
    return datos


def _rechazo(excepcion, contrasena=CONTRASENA):
    """Comprueba que el rechazo no filtra datos sensibles ni el motivo."""
    assert str(excepcion.value) == MENSAJE_PUBLICO
    assert contrasena not in str(excepcion.value)
    assert contrasena not in repr(excepcion.value)
    assert isinstance(excepcion.value, ErrorAutenticacion)


# ------------------------------------------------------------- casos válidos


def test_login_correcto_usuario_manual(entorno):
    resultado = autenticar_usuario(
        "pdi001", CONTRASENA, entorno.huella, ruta_base_datos=entorno.db
    )
    assert resultado.username == "pdi001"
    assert resultado.origin == "MANUAL"
    assert resultado.role == "PDI"
    assert resultado.device_id == "byod-001"
    print("[RF2] Usuario manual: certificado emparejado + contraseña correcta -> aceptado")


def test_login_correcto_usuario_rf5(tmp_path):
    pki.crear_ca(tmp_path)
    db = tmp_path / "data" / "rf1.sqlite3"
    ruta_credenciales = tmp_path / "privado" / "credenciales.csv"
    destino = tmp_path / "pki" / "clients" / "rf5"
    gestion.precargar_usuarios(3, ruta_base_datos=db, ruta_credenciales=ruta_credenciales)
    gestion.emitir_certificados(
        ruta_base_datos=db,
        directorio_destino=destino,
        ruta_ca_cert=tmp_path / "pki" / "ca" / "ca.crt",
        ruta_ca_key=tmp_path / "pki" / "ca" / "ca.key",
    )
    credenciales = gestion._leer_credenciales(ruta_credenciales)

    for registro in credenciales:
        huella = _huella_de_fichero(destino / f"{registro['username']}.crt")
        resultado = autenticar_usuario(
            registro["username"], registro["password"], huella, ruta_base_datos=db
        )
        assert resultado.origin == "RF5"
        assert resultado.role == registro["role"]
        assert resultado.device_id == registro["device_id"]
    print("[RF2] Usuarios RF5 (PDI, PAS, INVESTIGADOR) autenticados con su certificado")


def test_huella_en_mayusculas_se_normaliza(entorno):
    resultado = autenticar_usuario(
        "pdi001", CONTRASENA, entorno.huella.upper(), ruta_base_datos=entorno.db
    )
    assert resultado.username == "pdi001"
    print("[RF2] Huella en mayúsculas normalizada")


# ----------------------------------------------------------- casos rechazados


def test_contrasena_incorrecta(entorno):
    with pytest.raises(ContrasenaIncorrecta) as excepcion:
        autenticar_usuario(
            "pdi001", "contrasena-erronea", entorno.huella, ruta_base_datos=entorno.db
        )
    _rechazo(excepcion, "contrasena-erronea")
    print("[RF2] Contraseña incorrecta -> rechazado")


def test_usuario_inexistente(entorno):
    with pytest.raises(UsuarioInexistente) as excepcion:
        autenticar_usuario("nadie", CONTRASENA, entorno.huella, ruta_base_datos=entorno.db)
    _rechazo(excepcion)
    print("[RF2] Usuario inexistente -> rechazado")


def test_usuario_inexistente_tambien_calcula_scrypt(entorno, monkeypatch):
    """Mitigación de enumeración: se verifica contra un hash ficticio."""
    llamadas = []
    original = autenticacion.verificar_contrasena

    def espia(contrasena, hash_almacenado):
        llamadas.append(hash_almacenado)
        return original(contrasena, hash_almacenado)

    monkeypatch.setattr(autenticacion, "verificar_contrasena", espia)
    with pytest.raises(UsuarioInexistente):
        autenticar_usuario("nadie", CONTRASENA, entorno.huella, ruta_base_datos=entorno.db)
    assert len(llamadas) == 1 and llamadas[0].startswith("scrypt$")
    print("[RF2] Usuario inexistente: se ejecuta scrypt igualmente (sin atajo temporal)")


@pytest.mark.parametrize("estado", ["blocked", "revoked"])
def test_usuario_inactivo(entorno, estado):
    with conectar_base_datos(entorno.db) as conexion:
        conexion.execute("UPDATE users SET status = ? WHERE username = 'pdi001'", (estado,))
    with pytest.raises(UsuarioInactivo) as excepcion:
        autenticar_usuario("pdi001", CONTRASENA, entorno.huella, ruta_base_datos=entorno.db)
    _rechazo(excepcion)
    print(f"[RF2] Usuario con estado '{estado}' -> rechazado")


def test_certificado_no_asociado(entorno):
    """Certificado firmado por la CA pero sin emparejamiento en SQLite."""
    huella_ajena = _huella_de_fichero(entorno.certificado("sin-emparejar"))
    with pytest.raises(CertificadoNoEmparejado) as excepcion:
        autenticar_usuario("pdi001", CONTRASENA, huella_ajena, ruta_base_datos=entorno.db)
    _rechazo(excepcion)
    print("[RF2] Certificado válido de la CA pero no emparejado -> rechazado")


def test_certificado_asociado_a_otro_usuario(entorno):
    """pas001 presenta credenciales correctas con el dispositivo de pdi001."""
    entorno.usuario("pas001")
    entorno.emparejar("pas001", "byod-002", entorno.certificado("byod-002"))
    with pytest.raises(CertificadoDeOtroUsuario) as excepcion:
        autenticar_usuario("pas001", CONTRASENA, entorno.huella, ruta_base_datos=entorno.db)
    _rechazo(excepcion)
    print("[RF2] Certificado de otro usuario -> rechazado")


def test_dispositivo_revocado(entorno):
    with conectar_base_datos(entorno.db) as conexion:
        conexion.execute(
            "UPDATE device_pairings SET status = 'revoked' WHERE device_id = 'byod-001'"
        )
    with pytest.raises(DispositivoRevocado) as excepcion:
        autenticar_usuario("pdi001", CONTRASENA, entorno.huella, ruta_base_datos=entorno.db)
    _rechazo(excepcion)
    print("[RF2] Dispositivo revocado -> rechazado")


@pytest.mark.parametrize("huella", ["", "z" * 64, "a" * 63, "a" * 65, None, 123])
def test_huella_con_formato_invalido(entorno, huella):
    with pytest.raises(HuellaInvalida) as excepcion:
        autenticar_usuario("pdi001", CONTRASENA, huella, ruta_base_datos=entorno.db)
    _rechazo(excepcion)
    print("[RF2] Huella con formato inválido -> rechazada")


def test_todos_los_rechazos_comparten_mensaje_publico():
    clases = ErrorAutenticacion.__subclasses__()
    assert len(clases) == 7
    assert {str(clase()) for clase in clases} == {MENSAJE_PUBLICO}
    assert len({clase.motivo for clase in clases}) == 7
    print("[RF2] 7 motivos internos distintos, un único mensaje público")


def test_base_de_datos_inexistente_no_se_crea(tmp_path):
    ruta = tmp_path / "no-existe.sqlite3"
    with pytest.raises(FileNotFoundError):
        autenticar_usuario("pdi001", CONTRASENA, "a" * 64, ruta_base_datos=ruta)
    assert not ruta.exists()
    print("[RF2] Sin base de datos: error de configuración, no se crea una vacía")


# --------------------------------------------------------- seguridad de datos


def test_contrasena_nunca_se_guarda_en_claro(entorno):
    with pytest.raises(ContrasenaIncorrecta):
        autenticar_usuario("pdi001", "otra-contrasena-mala", entorno.huella, ruta_base_datos=entorno.db)
    autenticar_usuario("pdi001", CONTRASENA, entorno.huella, ruta_base_datos=entorno.db)

    with conectar_base_datos(entorno.db) as conexion:
        hash_guardado = conexion.execute(
            "SELECT password_hash FROM users WHERE username = 'pdi001'"
        ).fetchone()[0]
    contenido = entorno.db.read_bytes()
    assert hash_guardado.startswith("scrypt$")
    assert CONTRASENA.encode() not in contenido
    assert b"otra-contrasena-mala" not in contenido
    print("[RF2] SQLite solo contiene el hash scrypt; ninguna contraseña en claro")


# ------------------------------------------------- integración con mTLS real


def test_login_con_huella_obtenida_de_handshake_mtls_real(entorno):
    """Capa 1 real: la huella sale del certificado negociado en TLS 1.3."""
    pki.emitir_servidor(entorno.raiz)
    contexto_servidor = crear_contexto_tls_servidor(
        ruta_ca=entorno.raiz / "pki" / "ca" / "ca.crt",
        ruta_certificado=entorno.raiz / "pki" / "server" / "server.crt",
        ruta_clave=entorno.raiz / "pki" / "server" / "server.key",
    )
    resultados: queue.Queue = queue.Queue()
    escucha = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escucha.bind(("127.0.0.1", 0))
    escucha.listen(1)
    escucha.settimeout(5)

    def servidor():
        try:
            conexion, _ = escucha.accept()
            with contexto_servidor.wrap_socket(conexion, server_side=True) as segura:
                huella = huella_desde_conexion_tls(segura)
                usuario, contrasena = segura.recv(256).decode().split("\n", 1)
                resultado = autenticar_usuario(
                    usuario, contrasena, huella, ruta_base_datos=entorno.db
                )
                segura.sendall(b"OK")
                resultados.put((segura.version(), resultado))
        except Exception as exc:  # la prueba necesita ver el fallo
            resultados.put(("error", exc))
        finally:
            escucha.close()

    threading.Thread(target=servidor, daemon=True).start()

    directorio = entorno.raiz / "pki" / "clients" / "byod-001"
    cliente = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cliente.minimum_version = ssl.TLSVersion.TLSv1_3
    cliente.load_verify_locations(cafile=str(entorno.raiz / "pki" / "ca" / "ca.crt"))
    cliente.load_cert_chain(
        certfile=str(directorio / "byod-001.crt"),
        keyfile=str(directorio / "byod-001.key"),
    )
    with socket.create_connection(escucha.getsockname(), timeout=5) as conexion:
        with cliente.wrap_socket(conexion, server_hostname="localhost") as segura:
            segura.sendall(f"pdi001\n{CONTRASENA}".encode())
            assert segura.recv(16) == b"OK"

    version, resultado = resultados.get(timeout=5)
    assert version == "TLSv1.3"
    assert resultado.username == "pdi001"
    assert resultado.device_id == "byod-001"
    print("[RF2] Handshake mTLS TLS 1.3 real + credenciales -> sesión autorizable")
