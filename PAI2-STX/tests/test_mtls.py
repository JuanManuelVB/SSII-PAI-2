"""Pruebas de negociación TLS real entre un servidor y un cliente."""

from __future__ import annotations

import queue
import socket
import ssl
import threading

import pytest

from pki.scripts import pki
from src.server.tls import crear_contexto_tls_servidor


def _crear_material_mtls(ruta_base):
    """Crea una CA, un certificado de servidor y uno de cliente temporales."""
    pki.crear_ca(ruta_base)
    pki.emitir_servidor(ruta_base)
    pki.emitir_cliente(ruta_base, "cliente-prueba")
    return {
        "ca": ruta_base / "pki" / "ca" / "ca.crt",
        "certificado_servidor": ruta_base / "pki" / "server" / "server.crt",
        "clave_servidor": ruta_base / "pki" / "server" / "server.key",
        "certificado_cliente": (
            ruta_base / "pki" / "clients" / "cliente-prueba" / "cliente-prueba.crt"
        ),
        "clave_cliente": (
            ruta_base / "pki" / "clients" / "cliente-prueba" / "cliente-prueba.key"
        ),
    }


def _contexto_cliente(rutas, *, certificado=True, version=ssl.TLSVersion.TLSv1_3):
    """Crea el contexto de cliente usado por cada escenario de la prueba."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.minimum_version = version
    contexto.maximum_version = version
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_REQUIRED
    contexto.load_verify_locations(cafile=str(rutas["ca"]))
    if certificado:
        contexto.load_cert_chain(
            certfile=str(rutas["certificado_cliente"]),
            keyfile=str(rutas["clave_cliente"]),
        )
    return contexto


def _servidor_temporal(contexto_servidor):
    """Arranca un servidor local de una sola conexión y devuelve su dirección."""
    resultados = queue.Queue()
    escucha = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escucha.bind(("127.0.0.1", 0))
    escucha.listen(1)
    escucha.settimeout(5)

    def atender():
        try:
            conexion, _ = escucha.accept()
            with contexto_servidor.wrap_socket(conexion, server_side=True) as segura:
                segura.sendall(b"mTLS-ok")
                resultados.put(("ok", segura.version()))
        except Exception as exc:  # La prueba necesita observar el rechazo TLS.
            resultados.put(("error", exc))
        finally:
            escucha.close()

    threading.Thread(target=atender, daemon=True).start()
    return escucha.getsockname(), resultados


def test_negociacion_mtls_13_acepta_cliente_firmado_por_la_ca(tmp_path):
    """Un cliente con certificado válido negocia TLS 1.3 y recibe datos."""
    rutas = _crear_material_mtls(tmp_path)
    servidor = crear_contexto_tls_servidor(
        ruta_ca=rutas["ca"],
        ruta_certificado=rutas["certificado_servidor"],
        ruta_clave=rutas["clave_servidor"],
    )
    direccion, resultados = _servidor_temporal(servidor)

    cliente = _contexto_cliente(rutas)
    with socket.create_connection(direccion, timeout=5) as conexion:
        with cliente.wrap_socket(conexion, server_hostname="localhost") as segura:
            assert segura.version() == "TLSv1.3"
            assert segura.recv(32) == b"mTLS-ok"
            print("[mTLS] Cliente con certificado válido: handshake TLS 1.3 aceptado")

    assert resultados.get(timeout=5) == ("ok", "TLSv1.3")


def test_mtls_rechaza_cliente_sin_certificado(tmp_path):
    """El servidor no permite completar el handshake sin certificado cliente."""
    rutas = _crear_material_mtls(tmp_path)
    servidor = crear_contexto_tls_servidor(
        ruta_ca=rutas["ca"],
        ruta_certificado=rutas["certificado_servidor"],
        ruta_clave=rutas["clave_servidor"],
    )
    direccion, resultados = _servidor_temporal(servidor)

    cliente = _contexto_cliente(rutas, certificado=False)
    with socket.create_connection(direccion, timeout=5) as conexion:
        try:
            with cliente.wrap_socket(conexion, server_hostname="localhost") as segura:
                segura.recv(32)
        except ssl.SSLError:
            pass

    tipo, error = resultados.get(timeout=5)
    assert tipo == "error"
    assert isinstance(error, ssl.SSLError)
    print("[mTLS] Cliente sin certificado: handshake rechazado")


def test_mtls_rechaza_cliente_tls_12(tmp_path):
    """El servidor configurado para TLS 1.3 rechaza un cliente TLS 1.2."""
    rutas = _crear_material_mtls(tmp_path)
    servidor = crear_contexto_tls_servidor(
        ruta_ca=rutas["ca"],
        ruta_certificado=rutas["certificado_servidor"],
        ruta_clave=rutas["clave_servidor"],
    )
    direccion, resultados = _servidor_temporal(servidor)

    cliente = _contexto_cliente(
        rutas,
        version=ssl.TLSVersion.TLSv1_2,
    )
    with pytest.raises(ssl.SSLError):
        with socket.create_connection(direccion, timeout=5) as conexion:
            with cliente.wrap_socket(conexion, server_hostname="localhost"):
                pass

    tipo, error = resultados.get(timeout=5)
    assert tipo == "error"
    assert isinstance(error, ssl.SSLError)
    print("[mTLS] Cliente TLS 1.2: negociación rechazada")
