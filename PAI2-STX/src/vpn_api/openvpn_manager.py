"""Cliente para el socket UNIX de administración de OpenVPN.

No expone el socket a la red; usa únicamente 'status 3' y 'client-kill'.
"""
from __future__ import annotations

import socket
import time
from dataclasses import asdict, dataclass
from pathlib import Path


class OpenVPNManagerError(RuntimeError):
    """OpenVPN no responde, falla o devuelve un protocolo inesperado."""


class ClienteVPNNoEncontrado(LookupError):
    """No existe la conexión solicitada."""


class IdentidadVPNNoCoincide(PermissionError):
    """El identificador solicitado no pertenece al certificado esperado."""


@dataclass(frozen=True)
class VPNConnection:
    client_id: int
    common_name: str
    virtual_address: str
    real_address: str
    connected_since: str
    bytes_received: int
    bytes_sent: int

    def public(self) -> dict:
        return asdict(self)


def parse_status3(raw: str) -> list[VPNConnection]:
    """Analiza 'status 3' (TSV). Usa cabeceras, no posiciones fijas."""
    lines = [line.split('\t') for line in raw.splitlines()]
    headers = None
    for parts in lines:
        if len(parts) >= 3 and parts[0] == 'HEADER' and parts[1] == 'CLIENT_LIST':
            headers = parts[2:]
            break
    if headers is None:
        raise OpenVPNManagerError('OpenVPN no ha devuelto la cabecera CLIENT_LIST de status 3')

    result = []
    for parts in lines:
        if not parts or parts[0] != 'CLIENT_LIST':
            continue
        values = parts[1:]
        if len(values) < len(headers):
            raise OpenVPNManagerError('Fila CLIENT_LIST incompleta')
        d = dict(zip(headers, values))
        try:
            result.append(VPNConnection(
                client_id=int(d['Client ID']),
                common_name=d['Common Name'],
                real_address=d.get('Real Address', ''),
                virtual_address=d.get('Virtual Address', ''),
                connected_since=d.get('Connected Since', ''),
                bytes_received=int(d.get('Bytes Received') or 0),
                bytes_sent=int(d.get('Bytes Sent') or 0),
            ))
        except (ValueError, KeyError) as exc:
            raise OpenVPNManagerError('Datos CLIENT_LIST inválidos') from exc
    return result


class OpenVPNManager:
    def __init__(self, socket_path: str | Path = '/run/byodsec-vpn/management.sock', timeout: float = 3.0):
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def _command(self, command: str) -> str:
        # Jamás aceptar comandos arbitrarios o valores provenientes de HTTP.
        if command != 'status 3' and not (
            command.startswith('client-kill ') and
            command[len('client-kill '):].removesuffix(' HALT').isdigit() and
            command.endswith(' HALT')
        ):
            raise ValueError('Comando de administración no permitido')

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall((command + '\n').encode('ascii'))
                output = bytearray()
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        raise OpenVPNManagerError('Respuesta incompleta del socket OpenVPN')
                    output.extend(chunk)
                    if len(output) > 1024 * 1024:
                        raise OpenVPNManagerError('Respuesta excesiva de OpenVPN')
                    lines = output.decode('utf-8', errors='replace').splitlines()
                    # status devuelve END; client-kill responde SUCCESS/ERROR.
                    if command == 'status 3' and any(l.strip() == 'END' for l in lines):
                        return '\n'.join(lines)
                    if command != 'status 3':
                        answers = [l for l in lines if l.startswith(('SUCCESS:', 'ERROR:'))]
                        if answers:
                            return answers[-1]
        except (OSError, TimeoutError) as exc:
            raise OpenVPNManagerError(f'No se puede acceder al socket OpenVPN: {type(exc).__name__}') from exc

    def connections(self) -> list[VPNConnection]:
        return parse_status3(self._command('status 3'))

    def disconnect(self, client_id: int, expected_common_name: str) -> dict:
        if isinstance(client_id, bool) or not isinstance(client_id, int) or client_id < 0:
            raise ValueError('client_id no válido')
        if not expected_common_name or '\n' in expected_common_name or '\r' in expected_common_name:
            raise ValueError('expected_common_name no válido')
        candidate = next((item for item in self.connections() if item.client_id == client_id), None)
        if candidate is None:
            raise ClienteVPNNoEncontrado('Conexión VPN inexistente')
        if candidate.common_name != expected_common_name:
            raise IdentidadVPNNoCoincide('El certificado no corresponde a esa conexión')

        # HALT indica al cliente que detenga la sesión en lugar de reiniciarla.
        answer = self._command(f'client-kill {client_id} HALT')
        if not answer.startswith('SUCCESS:'):
            raise OpenVPNManagerError('OpenVPN rechazó la orden de desconexión')
        # No afirmar que está desconectado sin una observación posterior.
        for attempt in range(5):
            if not any(c.client_id == client_id for c in self.connections()):
                return {'status': 'disconnected', 'client_id': client_id,
                        'common_name': expected_common_name}
            if attempt < 4:
                time.sleep(0.2)
        raise OpenVPNManagerError('OpenVPN aceptó la orden pero la conexión sigue activa')
