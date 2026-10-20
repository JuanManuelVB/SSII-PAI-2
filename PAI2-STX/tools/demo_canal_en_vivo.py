"""Demostración REAL del canal BYODSEC TLS 1.3/mTLS (NO es un test unitario).

Ejemplo, en Windows/PowerShell dentro del proyecto:
    py -m tools.demo_canal_en_vivo --usuario rf5_inv_001

Requiere gateway activo y la extensión Camino A (/api/v1/resources/*).
No vuelca en pantalla ni ficheros contraseñas, claves privadas o tokens.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import socket
import ssl
import sys
from urllib.parse import urlsplit

from src.client.servicio_consola import (
    CA_DEFECTO,
    ClienteConsola,
    contexto_cliente,
    encontrar_identidades,
)


def comprobar_tls_real(url, identidad):
    """Handshake TLS real con el servidor y el MISMO certificado del login."""
    destino = urlsplit(url)
    if destino.scheme != "https" or not destino.hostname:
        raise ValueError("La URL debe ser HTTPS")
    host = destino.hostname
    puerto = destino.port or 443
    contexto = contexto_cliente(CA_DEFECTO, identidad.certificado, identidad.clave)
    with socket.create_connection((host, puerto), timeout=8) as tcp:
        with contexto.wrap_socket(tcp, server_hostname=host) as conexion:
            # El cliente comprueba CA y nombre mediante contexto_cliente.
            version = conexion.version()
            suite = conexion.cipher()[0] if conexion.cipher() else "desconocida"
            huella = hashlib.sha256(conexion.getpeercert(binary_form=True)).hexdigest()
            # Completar una solicitud HTTP para forzar la verificación mTLS en TLS1.3.
            conexion.sendall((
                f"GET /api/v1/resources/demo HTTP/1.1\r\n"
                f"Host: {host}\r\nConnection: close\r\n\r\n"
            ).encode("ascii"))
            conexion.settimeout(8)
            respuesta = conexion.recv(4096)
            primera_linea = respuesta.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            if version != "TLSv1.3":
                raise RuntimeError(f"Version TLS negociada distinta de TLS 1.3: {version}")
            if "401" not in primera_linea:
                raise RuntimeError(
                    f"El recurso sin token NO devolvió HTTP 401: {primera_linea}. "
                    "Comprueba la configuración del gateway."
                )
            return version, suite, huella[:16], primera_linea


def main():
    parser = argparse.ArgumentParser(
        description="Demostración en vivo Windows -> Ubuntu de HTTPS TLS1.3/mTLS y RF2/RF4"
    )
    parser.add_argument("--url", default="https://localhost:9443")
    parser.add_argument("--usuario", default="rf5_inv_001")
    parser.add_argument("--dispositivo", default=None)
    parser.add_argument("--mensaje", default="Mensaje corporativo BYODSEC: transmision cifrada de Windows a Ubuntu")
    args = parser.parse_args()
    if not (1 <= len(args.mensaje) <= 2048):
        parser.error("El mensaje debe tener de 1 a 2048 caracteres")
    candidatos = [i for i in encontrar_identidades()
                  if i.usuario == args.usuario and
                  (args.dispositivo is None or i.dispositivo == args.dispositivo)]
    if not candidatos:
        raise SystemExit(f"No existe un par .crt/.key para {args.usuario} en pki/clients")
    if len(candidatos) > 1:
        print("Hay varios dispositivos de ese usuario. Elige uno con --dispositivo:")
        for identidad in candidatos:
            print("  ", identidad.dispositivo)
        raise SystemExit(2)
    identidad = candidatos[0]
    print("\n=== BYODSEC · DEMOSTRACIÓN REAL (no pytest) ===")
    print("Cliente Windows -> gateway Ubuntu WSL2:", args.url)
    print("Usuario:", identidad.usuario, "· dispositivo:", identidad.dispositivo)
    print("\n[1/5] Handshake TLS real con certificado cliente y CA corporativa ...")
    version, suite, huella, sin_token = comprobar_tls_real(args.url, identidad)
    print("  TLS negociado:", version)
    print("  Suite negociada:", suite)
    print("  Huella SHA-256 servidor (16 hex):", huella)
    print("  Acceso SIN iniciar sesión:", sin_token, "(rechazado correctamente)")
    print("\n[2/5] Introduce contraseña corporativa (no se muestra) ...")
    clave = getpass.getpass("Contraseña corporativa: ")
    cliente = ClienteConsola(url=args.url)
    sesion_activa = False
    try:
        resultado = cliente.iniciar_sesion(identidad, clave)
        sesion_activa = True
        del clave
        print("  RF2:", resultado["codigo"], "·", resultado["usuario"], "autenticado por mTLS y contraseña")
        datos = cliente.consultar_sesion()
        print("  GET /sessions/me: HTTP 200 · dispositivo:", datos.get("device_id"))
        print("\n[3/5] Acceso REAL a recurso corporativo protegido ...")
        documento = cliente.consultar_recurso()
        print("  GET /resources/demo: HTTP 200 · contenido:", documento.get("contenido"))
        print("\n[4/5] ENVÍO REAL cifrado Windows -> Ubuntu -> Windows ...")
        print("  Mensaje enviado en cuerpo HTTPS:", args.mensaje)
        recibido = cliente.enviar_mensaje_seguro(args.mensaje)
        print("  POST /resources/echo: HTTP 200")
        print("  Bytes recibidos por Ubuntu:", recibido["bytes"])
        print("  SHA-256 devuelto y verificado:", recibido["sha256"])
        print("\n[5/5] RF4 logout real y rechazo de token revocado ...")
        cerrado = cliente.cerrar_sesion(comprobar_revocacion=True)
        sesion_activa = False
        print("  Logout: HTTP", cerrado.respuesta)
        print("  Petición nueva con token revocado: HTTP", cerrado.codigo_comprobacion)
        if not cerrado.rechazo_comprobado:
            raise RuntimeError("El token antiguo NO fue rechazado")
        print("\nDEMO SUPERADA: mTLS/TLS1.3 + login + tráfico HTTPS + logout + HTTP 401")
        print("Acompaña esta ejecución de una captura Wireshark/tcpdump de tcp.port==9443.")
    finally:
        if sesion_activa:
            print("AVISO: la sesión podría seguir activa. Cierra RF4 desde la interfaz BYODSEC.")
        cliente.desconectar_local()


if __name__ == "__main__":
    try:
        main()
    except (ConnectionError, OSError, ssl.SSLError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
