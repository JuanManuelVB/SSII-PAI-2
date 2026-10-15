"""Pruebas unitarias del contexto TLS 1.3 del servidor."""

from __future__ import annotations

import ssl

import pytest

from pki.scripts import pki
from src.server.tls import crear_contexto_tls_servidor


def _crear_material_tls(ruta_base):
    """Crea una CA y un certificado de servidor temporales para la prueba."""
    pki.crear_ca(ruta_base)
    pki.emitir_servidor(ruta_base)
    return {
        "ca": ruta_base / "pki" / "ca" / "ca.crt",
        "certificado": ruta_base / "pki" / "server" / "server.crt",
        "clave": ruta_base / "pki" / "server" / "server.key",
    }


def test_contexto_exige_tls_13_y_certificado_cliente(tmp_path):
    """El servidor solo permite TLS 1.3 y exige mTLS."""
    rutas = _crear_material_tls(tmp_path)

    contexto = crear_contexto_tls_servidor(
        ruta_ca=rutas["ca"],
        ruta_certificado=rutas["certificado"],
        ruta_clave=rutas["clave"],
    )

    assert contexto.minimum_version == ssl.TLSVersion.TLSv1_3
    assert contexto.maximum_version == ssl.TLSVersion.TLSv1_3
    assert contexto.verify_mode == ssl.CERT_REQUIRED
    print("[TLS] Version permitida: TLS 1.3; certificados cliente: obligatorios")


def test_contexto_falla_si_falta_material_tls(tmp_path):
    """La configuración falla explícitamente si falta un archivo PKI."""
    with pytest.raises(FileNotFoundError, match="certificado de la CA"):
        crear_contexto_tls_servidor(
            ruta_ca=tmp_path / "ca.crt",
            ruta_certificado=tmp_path / "server.crt",
            ruta_clave=tmp_path / "server.key",
        )
    print("[TLS] Material incompleto rechazado explícitamente")
