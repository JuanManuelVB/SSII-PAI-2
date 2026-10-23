"""Pruebas de la nueva comparación RS3 (sin credenciales reales)."""
import asyncio
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from tools.comparativa_cifrado import (comparar, estadisticas, payload, sobrecostes,
                                       servidor_http_local)
from tools.servidor_sin_cifrar import app


def test_echo_http_local_igual_longitud_y_digest():
    import hashlib
    with TestClient(app) as cliente:
        mensaje = "A" * 256
        respuesta = cliente.post('/echo', json={"mensaje": mensaje})
        assert respuesta.status_code == 200
        assert respuesta.json() == {"status": "processed", "bytes": 256,
                                   "sha256": hashlib.sha256(mensaje.encode()).hexdigest()}


def test_http_no_expone_login_ni_admite_mensajes_invalidos():
    with TestClient(app) as cli:
        assert cli.post('/echo', json={"mensaje": ""}).status_code == 422
        assert cli.post('/echo', json={"mensaje": "X" * 2049}).status_code == 422
        assert cli.post('/api/v1/sessions/login', json={}).status_code == 404


def test_payload_tamano_y_estadisticas():
    assert len(payload(2, 10, 256).encode()) == 256
    assert len(payload(1, 1, 1)) == 1
    assert estadisticas([])["p95"] is None
    assert estadisticas([5, 8, 10])["p95"] == 8


def test_no_calcular_overhead_ante_fallos():
    bueno = {"errores": 0, "mensajes_confirmados": 10,
             "latencia_mensaje_ms": {"media": 10.0}, "throughput_mensajes_por_s": 20.0}
    mal = {**bueno, "errores": 1, "mensajes_confirmados": 9}
    assert sobrecostes(mal, bueno) is None
    assert sobrecostes(bueno, mal) is None
    assert sobrecostes(bueno, bueno) == {"incremento_latencia_media_pct": 0.0, "perdida_throughput_pct": 0.0}


@pytest.mark.parametrize('url', ['http://localhost:9443', 'https://example.com:9443'])
def test_no_permite_gateway_remoto_o_sin_tls(url):
    with pytest.raises(ValueError):
        asyncio.run(comparar(1, 1, 256, 1, url_tls=url))


def test_autoinicio_y_cierre_de_linea_base_http():
    async def prueba():
        with socket.socket() as temporal:
            temporal.bind(('127.0.0.1', 0))
            puerto = temporal.getsockname()[1]
        async with servidor_http_local(puerto) as (url, _pid):
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.post(url + '/echo', json={'mensaje': 'prueba RS3'})
                assert r.status_code == 200
                assert r.json()['bytes'] == len('prueba RS3')
        # Tras salir del contexto el proceso HTTP debe estar cerrado.
        async with httpx.AsyncClient(trust_env=False, timeout=1) as c:
            with pytest.raises(httpx.ConnectError):
                await c.get(url + '/health')
    asyncio.run(prueba())
