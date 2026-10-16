"""Administración VPN 100 % HTTPS/REST, sin socket de gestión OpenVPN.

REQUIERE OpenVPN Access Server >=3.2, NO OpenVPN Community.
Documentación oficial: https://openvpn.net/as-docs/rest-api/
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx


class AccessServerError(RuntimeError):
    """Fallo de autenticación o de API REST de Access Server."""


@dataclass(frozen=True)
class ConfigAccessServer:
    url: str
    username: str
    password: str
    ca_bundle: str | bool = True
    timeout: float = 8.0

    @classmethod
    def desde_entorno(cls) -> "ConfigAccessServer":
        url = os.environ.get('BYODSEC_AS_URL', '').rstrip('/')
        username = os.environ.get('BYODSEC_AS_ADMIN_USER', '')
        password = os.environ.get('BYODSEC_AS_ADMIN_PASSWORD', '')
        ca_bundle = os.environ.get('BYODSEC_AS_CA_BUNDLE', '') or True
        if not url or not username or not password:
            raise AccessServerError('Falta BYODSEC_AS_URL o credenciales de administración en el entorno')
        parts = urlsplit(url)
        if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment or parts.query:
            raise AccessServerError('BYODSEC_AS_URL debe ser un origen HTTPS sin credenciales ni consultas')
        # Las credenciales de API nunca pueden enviarse a una dirección HTTP.
        if parts.path.rstrip('/') not in ('', '/api'):
            raise AccessServerError('BYODSEC_AS_URL debe ser el origen del servidor (sin rutas)')
        return cls(url=url.removesuffix('/api'), username=username, password=password, ca_bundle=ca_bundle)


class AccessServerClient:
    """Cliente HTTP que invoca únicamente los endpoints REST oficiales."""

    def __init__(self, config: ConfigAccessServer, transport: httpx.BaseTransport | None = None):
        self.config = config
        self._transport = transport

    def _cliente(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.config.url, verify=self.config.ca_bundle,
            timeout=self.config.timeout, follow_redirects=False,
            trust_env=False, transport=self._transport,
        )

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        try:
            response.raise_for_status()
            if response.status_code == 204 or not response.content:
                return {}
            body = response.json()
            if not isinstance(body, dict):
                raise AccessServerError('Respuesta REST inesperada')
            return body
        except httpx.HTTPStatusError as exc:
            raise AccessServerError(f'Access Server devolvió HTTP {exc.response.status_code}') from exc
        except ValueError as exc:
            raise AccessServerError('Access Server no devolvió JSON válido') from exc

    @staticmethod
    def _confirmar_respuesta_actualizacion(response: httpx.Response) -> dict[str, Any]:
        """/api/userprop/set devuelve HTTP 200 de éxito sin esquema JSON fijo.

        Conservamos el rechazo de cualquier error HTTP; no exigimos dict.
        """
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise AccessServerError(f'Access Server devolvió HTTP {exc.response.status_code}') from exc
        if response.status_code != 200:
            raise AccessServerError(f'Código inesperado de actualización VPN: HTTP {response.status_code}')
        return {'status': 'accepted', 'http_status': response.status_code}

    def _authenticated(self, method: str, route: str, payload: dict | list | None = None) -> dict:
        try:
            with self._cliente() as client:
                login = self._json(client.post('/api/auth/login/userpassword', json={
                    'username': self.config.username,
                    'password': self.config.password,
                    'request_admin': True,
                }))
                token = login.get('auth_token')
                if not isinstance(token, str) or not token:
                    raise AccessServerError('No se obtuvo un token administrativo')
                headers = {'X-OpenVPN-As-AuthToken': token}
                response = client.request(method, route, json=payload, headers=headers)
                # Este endpoint documenta 200 sin objeto JSON obligatorio.
                # La validación estricta de los demás endpoints no cambia.
                if route == '/api/userprop/set':
                    return self._confirmar_respuesta_actualizacion(response)
                return self._json(response)
        except httpx.RequestError as exc:
            raise AccessServerError('No se pudo contactar por HTTPS con Access Server') from exc

    def status(self) -> dict[str, Any]:
        return self._authenticated('GET', '/api/vpn/status')

    def conexiones_usuario(self, username: str) -> list[dict]:
        if not username or not isinstance(username, str):
            raise ValueError('username obligatorio')
        estado = self.status()
        clientes = estado.get('vpn_clients', [])
        if not isinstance(clientes, list):
            raise AccessServerError('El endpoint /vpn/status no incluye vpn_clients válidos')
        # Filtrar por cuenta autenticada, no por un username enviado en JSON.
        return [c for c in clientes if isinstance(c, dict) and c.get('username') == username]

    def desconectar_usuario(self, username: str) -> dict:
        if not username or not isinstance(username, str):
            raise ValueError('username obligatorio')
        try:
            return self._authenticated('POST', '/api/vpn/client/disconnect', {
                'users': [username],
                'reason': 'BYODSEC: logout de la cuenta autenticada',
                'client_reason': 'La sesión BYODSEC ha finalizado',
            })
        except AccessServerError as exc:
            # Access Server puede devolver 404 si el usuario todavía no ha
            # creado un túnel. Confirmamos REST que NO haya conexiones antes
            # de considerarlo correctamente desconectado.
            if 'HTTP 404' in str(exc) and not self.conexiones_usuario(username):
                return {'status': 'already_disconnected'}
            raise

    def fijar_acceso(self, username: str, *, permitido: bool) -> dict:
        """POST /userprop/set: deny=true bloquea nuevos logins VPN.

        Se modifica SOLO el usuario de RF2, identificado previamente en el
        servidor. Nunca recibe nombres desde el JSON no autenticado del cliente.
        """
        if not isinstance(username, str) or not username or len(username) > 64:
            raise ValueError("usuario VPN inválido")
        return self._authenticated('POST', '/api/userprop/set', [
            {'name': username, 'deny': not permitido, 'autologin': False}
        ])

    def crear_usuario_bloqueado(self, username: str) -> dict:
        """Da de alta UNA identidad de laboratorio, inhabilitada por defecto.

        No genera contraseñas Access Server: estas se administran por separado.
        No debe exponerse como endpoint de usuario normal.
        """
        if not isinstance(username, str) or not username or len(username) > 64:
            raise ValueError("usuario VPN inválido")
        return self._authenticated('POST', '/api/users/create', {
            'name': username, 'deny': True, 'autologin': False,
            'admin': False, 'allow_generate_profiles': True,
        })
