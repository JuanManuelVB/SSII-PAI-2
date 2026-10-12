"""Smoke test mTLS 1.3 en 127.0.0.1, sin activar ni modificar FastAPI.

No sustituye la comprobación en SQLite y sesiones que corresponde a RF2.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import threading
from pathlib import Path

from .cli import RAIZ


def probar_mtls(raiz: Path = RAIZ, *, usuario: str = 'rf5_inv_001',
                sin_certificado: bool = False) -> bool:
    ca = raiz / 'pki' / 'ca' / 'ca.crt'
    servidor_crt = raiz / 'pki' / 'server' / 'server.crt'
    servidor_key = raiz / 'pki' / 'server' / 'server.key'
    cliente_crt = raiz / 'pki' / 'clients' / 'rf5' / f'{usuario}.crt'
    cliente_key = raiz / 'pki' / 'clients' / 'rf5' / f'{usuario}.key'
    obligatorios = [ca, servidor_crt, servidor_key]
    if not sin_certificado:
        obligatorios += [cliente_crt, cliente_key]
    for archivo in obligatorios:
        if not archivo.is_file():
            raise FileNotFoundError(f'Archivo requerido no encontrado: {archivo}')

    servidor = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    servidor.minimum_version = servidor.maximum_version = ssl.TLSVersion.TLSv1_3
    servidor.verify_mode = ssl.CERT_REQUIRED
    servidor.load_verify_locations(cafile=str(ca))
    servidor.load_cert_chain(certfile=str(servidor_crt), keyfile=str(servidor_key))

    cliente = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    cliente.minimum_version = cliente.maximum_version = ssl.TLSVersion.TLSv1_3
    cliente.check_hostname = True
    if not sin_certificado:
        cliente.load_cert_chain(certfile=str(cliente_crt), keyfile=str(cliente_key))

    resultados: dict[str, object] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(5)
        puerto = listener.getsockname()[1]

        def atender() -> None:
            try:
                with listener.accept()[0] as sock:
                    sock.settimeout(5)
                    with servidor.wrap_socket(sock, server_side=True) as seguro:
                        datos = seguro.recv(5)
                        resultados['servidor_certificado_cliente'] = bool(seguro.getpeercert())
                        resultados['servidor_tls'] = seguro.version()
                        if datos == b'hola\n':
                            seguro.sendall(b'ok\n')
            except (OSError, ssl.SSLError) as exc:
                resultados['rechazo_servidor'] = str(exc)

        hilo = threading.Thread(target=atender, daemon=True)
        hilo.start()
        try:
            with socket.create_connection(('127.0.0.1', puerto), timeout=5) as s:
                s.settimeout(5)
                with cliente.wrap_socket(s, server_hostname='localhost') as seguro:
                    resultados['cliente_tls'] = seguro.version()
                    seguro.sendall(b'hola\n')
                    resultados['respuesta'] = seguro.recv(3)
        except (OSError, ssl.SSLError) as exc:
            resultados['rechazo_cliente'] = str(exc)
        hilo.join(timeout=6)
        if hilo.is_alive():
            raise RuntimeError('La prueba mTLS no ha podido finalizar')

    aprobado = (resultados.get('servidor_certificado_cliente') is True
                and resultados.get('servidor_tls') == 'TLSv1.3'
                and resultados.get('cliente_tls') == 'TLSv1.3'
                and resultados.get('respuesta') == b'ok\n')
    if sin_certificado:
        return not aprobado and ('rechazo_servidor' in resultados or 'rechazo_cliente' in resultados)
    return aprobado


def main() -> int:
    parser = argparse.ArgumentParser(description='Prueba TCP de TLS 1.3 + certificado de cliente')
    parser.add_argument('--usuario', default='rf5_inv_001')
    parser.add_argument('--sin-certificado', action='store_true', help='prueba negativa esperada')
    args = parser.parse_args()
    try:
        paso = probar_mtls(usuario=args.usuario, sin_certificado=args.sin_certificado)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'Error: {exc}')
        return 1
    print('PRUEBA OK' if paso else 'PRUEBA FALLIDA')
    print('Caso: rechazo sin certificado' if args.sin_certificado else 'Caso: mTLS autenticado, TLS 1.3')
    return 0 if paso else 1


if __name__ == '__main__':
    raise SystemExit(main())
