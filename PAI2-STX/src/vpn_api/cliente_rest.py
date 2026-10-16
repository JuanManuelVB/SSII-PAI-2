"""Cliente REST que usará el gateway RF4, sin permisos sobre sockets ni sudo."""
from __future__ import annotations

import httpx


class VPNRestClient:
    def __init__(self, base_url: str, service_token: str, timeout: float = 3.0):
        self.base_url = base_url.rstrip('/')
        self.token = service_token
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs) -> dict:
        # Preferir localhost forwarding WSL2. En LAN, exigir HTTPS/mTLS.
        with httpx.Client(timeout=self.timeout, trust_env=False) as client:
            response = client.request(method, f'{self.base_url}{path}',
                headers={'Authorization': f'Bearer {self.token}'}, **kwargs)
            response.raise_for_status()
            return response.json()

    def status(self) -> dict:
        return self._request('GET', '/api/v1/vpn/status')

    def connections(self) -> dict:
        return self._request('GET', '/api/v1/vpn/connections')

    def disconnect(self, client_id: int, expected_common_name: str) -> dict:
        return self._request('POST', '/internal/vpn/disconnect',
            json={'client_id': client_id, 'expected_common_name': expected_common_name})
