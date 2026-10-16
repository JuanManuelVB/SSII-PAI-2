"""Regresión: /userprop/set puede devolver una respuesta no objeto."""
import httpx
import pytest
from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer, AccessServerError


@pytest.mark.parametrize('respuesta', [
    httpx.Response(200, json=True),
    httpx.Response(200, json=[]),
    httpx.Response(200, json=None),
    httpx.Response(200, content=b''),
    httpx.Response(200, json={'ok': True}),
])
def test_userprop_set_acepta_200_sin_dict(respuesta):
    rutas = []
    def handler(request):
        rutas.append(request.url.path)
        if request.url.path == '/api/auth/login/userpassword':
            return httpx.Response(200, json={'auth_token': 'falso'})
        if request.url.path == '/api/userprop/set':
            assert request.method == 'POST'
            assert b'"deny":true' in request.content or b'"deny": true' in request.content
            return respuesta
        raise AssertionError('Ruta inesperada')
    api = AccessServerClient(ConfigAccessServer('https://localhost:943', 'admin', 'falsa'),
                             httpx.MockTransport(handler))
    assert api.fijar_acceso('rf5_inv_001', permitido=False) == {'status': 'accepted', 'http_status': 200}
    assert rutas == ['/api/auth/login/userpassword', '/api/userprop/set']


@pytest.mark.parametrize('codigo', [400, 401, 403, 404, 500])
def test_userprop_set_rechaza_errores(codigo):
    def handler(request):
        if request.url.path == '/api/auth/login/userpassword':
            return httpx.Response(200, json={'auth_token': 'falso'})
        return httpx.Response(codigo, json={'message': 'error simulado'})
    api = AccessServerClient(ConfigAccessServer('https://localhost:943', 'admin', 'falsa'),
                             httpx.MockTransport(handler))
    with pytest.raises(AccessServerError, match=f'HTTP {codigo}'):
        api.fijar_acceso('rf5_inv_001', permitido=False)


def test_status_sigue_exigiendo_dict():
    def handler(request):
        if request.url.path == '/api/auth/login/userpassword':
            return httpx.Response(200, json={'auth_token': 'falso'})
        return httpx.Response(200, json=True)
    api = AccessServerClient(ConfigAccessServer('https://localhost:943', 'admin', 'falsa'),
                             httpx.MockTransport(handler))
    with pytest.raises(AccessServerError, match='Respuesta REST inesperada'):
        api.status()
