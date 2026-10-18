"""Extra (+10 %): ataques controlados contra el gateway REAL en marcha.

A diferencia de ``tools.ataque_opcional`` (propiedades TLS en loopback con
certificados efímeros), esto comprueba que el GATEWAY del laboratorio
(https://localhost:9443, TLS 1.3 + mTLS) RECHAZA e IDENTIFICA intentos de
acceso no autorizados. Son pruebas negativas defensivas: ninguna debe tener
éxito; cada rechazo queda además en el registro de auditoría (RS4).

Escenarios (todos contra el servicio en marcha):
  1. Cliente SIN certificado mTLS                 -> handshake rechazado
  2. Cliente con certificado de una CA AJENA      -> handshake rechazado
  3. Credenciales incorrectas (contraseña mala)   -> HTTP 401
  4. Suplantación: certificado propio + contraseña de OTRO usuario -> HTTP 401
  5. Token robado reutilizado con OTRO certificado -> HTTP 401
  6. Reutilización del token tras logout (RF4)     -> HTTP 401

El servidor falso con CA desconocida y la reconexión tras revocación de
certificado se complementan con ``tools.ataque_opcional`` y con las pruebas
manuales del túnel real (ver docs/procedimientos_6_10.md).

Uso (con el gateway en marcha): python -m tools.ataques_vpn_real \
    --json evidencias/ataques/vpn_real.json
"""
from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.rf2.autenticacion import mensaje_a_firmar
from tools.carga_gateway import cargar_identidades

RAIZ = Path(__file__).resolve().parents[1]
CA = RAIZ / "pki" / "ca" / "ca.crt"


def _ctx(cert: Path | None = None, key: Path | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(CA))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if cert and key:
        ctx.load_cert_chain(str(cert), str(key))
    return ctx


def _firmar(clave, mensaje: bytes) -> str:
    if isinstance(clave, rsa.RSAPrivateKey):
        return base64.b64encode(clave.sign(mensaje, padding.PKCS1v15(), hashes.SHA256())).decode()
    return base64.b64encode(clave.sign(mensaje, ec.ECDSA(hashes.SHA256()))).decode()


def _login(url: str, ident: dict, password: str | None = None) -> httpx.Response:
    """Realiza un login RF2 y devuelve la respuesta del endpoint /login."""
    ctx = _ctx(ident["cert"], ident["key"])
    clave = serialization.load_pem_private_key(ident["key"].read_bytes(), password=None)
    cert_pem = ident["cert"].read_text(encoding="ascii")
    with httpx.Client(verify=ctx, base_url=url, timeout=15.0) as cli:
        des = cli.post("/api/v1/sessions/challenge",
                       json={"username": ident["usuario"], "device_id": ident["device_id"]})
        nonce = des.json()["nonce"]
        firma = _firmar(clave, mensaje_a_firmar(nonce, ident["usuario"], ident["device_id"]))
        return cli.post("/api/v1/sessions/login", json={
            "username": ident["usuario"], "device_id": ident["device_id"],
            "password": password if password is not None else ident["password"],
            "nonce": nonce, "certificate": cert_pem, "signature": firma})


# --------------------------------------------------------------------- ataques
def _intento_mtls(host: str, puerto: int, ctx: ssl.SSLContext) -> dict:
    """Intenta hablar HTTP sobre mTLS. Rechazado si no llega respuesta HTTP real.

    En TLS 1.3 el cliente termina el handshake antes de que el servidor valide
    su certificado, así que el rechazo del servidor llega después: o como alerta
    SSL, o como cierre de conexión (recv vacío). Solo se considera ACEPTADO si el
    servidor devuelve una respuesta HTTP.
    """
    try:
        with socket.create_connection((host, puerto), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname="localhost") as tls:
                tls.sendall(b"GET /api/v1/sessions/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                datos = tls.recv(32)
        if datos.startswith(b"HTTP"):
            return {"rechazado": False, "detalle": "el servidor devolvió respuesta HTTP"}
        return {"rechazado": True, "detalle": "el servidor cerró la conexión sin servir (sin respuesta HTTP)"}
    except (ssl.SSLError, OSError) as exc:
        return {"rechazado": True, "detalle": f"handshake/canal rechazado ({type(exc).__name__})"}


def sin_certificado_mtls(url: str, host: str, puerto: int) -> dict:
    """El gateway exige certificado de cliente: sin él, no hay canal."""
    return _intento_mtls(host, puerto, _ctx())


def certificado_ca_ajena(url: str, host: str, puerto: int) -> dict:
    """Certificado válido pero firmado por una CA que el gateway no reconoce."""
    with tempfile.TemporaryDirectory(prefix="pai2-atq-") as tmp:
        d = Path(tmp)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ahora = datetime.now(timezone.utc)
        ca_sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA Atacante")])
        ca_cert = (x509.CertificateBuilder().subject_name(ca_sub).issuer_name(ca_sub)
                   .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(ahora - timedelta(minutes=1)).not_valid_after(ahora + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(ca_key, hashes.SHA256()))
        cl_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cl_cert = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dispositivo-falso")]))
                   .issuer_name(ca_sub).public_key(cl_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(ahora - timedelta(minutes=1)).not_valid_after(ahora + timedelta(days=1))
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                   .sign(ca_key, hashes.SHA256()))
        crt = d / "falso.crt"; key = d / "falso.key"
        crt.write_bytes(cl_cert.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(cl_key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return _intento_mtls(host, puerto, _ctx(crt, key))


def credenciales_incorrectas(url: str, ident: dict) -> dict:
    r = _login(url, ident, password="contrasena-incorrecta-XYZ")
    return {"rechazado": r.status_code == 401, "detalle": f"HTTP {r.status_code}"}


def suplantacion_password_ajena(url: str, ident_a: dict, ident_b: dict) -> dict:
    """Certificado y usuario de A, pero la contraseña de B: debe fallar."""
    r = _login(url, ident_a, password=ident_b["password"])
    return {"rechazado": r.status_code == 401, "detalle": f"HTTP {r.status_code}"}


def token_robado_otro_certificado(url: str, ident_a: dict, ident_b: dict) -> dict:
    """Token legítimo de A reutilizado sobre el certificado de B: debe fallar."""
    login = _login(url, ident_a)
    if login.status_code != 200:
        return {"rechazado": False, "detalle": f"no se pudo obtener token legítimo (HTTP {login.status_code})"}
    token = login.json()["access_token"]
    ctx_b = _ctx(ident_b["cert"], ident_b["key"])
    with httpx.Client(verify=ctx_b, base_url=url, timeout=15.0) as cli:
        r = cli.get("/api/v1/sessions/me", headers={"Authorization": f"Bearer {token}"})
    # Limpieza: cerrar la sesión legítima de A.
    ctx_a = _ctx(ident_a["cert"], ident_a["key"])
    with httpx.Client(verify=ctx_a, base_url=url, timeout=15.0) as cli:
        cli.post("/api/v1/sessions/logout", headers={"Authorization": f"Bearer {token}"})
    return {"rechazado": r.status_code == 401, "detalle": f"HTTP {r.status_code}"}


def reutilizacion_tras_logout(url: str, ident: dict) -> dict:
    """Tras logout, el token anterior no debe volver a validar (RF4)."""
    login = _login(url, ident)
    if login.status_code != 200:
        return {"rechazado": False, "detalle": f"no se pudo iniciar sesión (HTTP {login.status_code})"}
    token = login.json()["access_token"]
    ctx = _ctx(ident["cert"], ident["key"])
    with httpx.Client(verify=ctx, base_url=url, timeout=15.0) as cli:
        cli.post("/api/v1/sessions/logout", headers={"Authorization": f"Bearer {token}"})
        r = cli.get("/api/v1/sessions/me", headers={"Authorization": f"Bearer {token}"})
    return {"rechazado": r.status_code == 401, "detalle": f"HTTP {r.status_code} con el token ya cerrado"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Ataques controlados contra el gateway real (+10%)")
    ap.add_argument("--url", default="https://localhost:9443")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--puerto", type=int, default=9443)
    ap.add_argument("--json", type=Path, default=RAIZ / "evidencias" / "ataques" / "vpn_real.json")
    args = ap.parse_args()

    identidades = cargar_identidades()
    if len(identidades) < 2:
        raise SystemExit("Se necesitan al menos 2 identidades RF5 con certificado y contraseña.")
    a, b = identidades[0], identidades[1]

    pruebas = {
        "cliente_sin_certificado_mtls": sin_certificado_mtls(args.url, args.host, args.puerto),
        "cliente_certificado_ca_ajena": certificado_ca_ajena(args.url, args.host, args.puerto),
        "credenciales_incorrectas": credenciales_incorrectas(args.url, a),
        "suplantacion_password_ajena": suplantacion_password_ajena(args.url, a, b),
        "token_robado_otro_certificado": token_robado_otro_certificado(args.url, a, b),
        "reutilizacion_token_tras_logout": reutilizacion_tras_logout(args.url, a),
    }
    documento = {
        "fecha_utc": datetime.now(timezone.utc).isoformat(),
        "objetivo": args.url,
        "entorno": "gateway del laboratorio en marcha, TLS 1.3 + mTLS",
        "resumen": {n: bool(r["rechazado"]) for n, r in pruebas.items()},
        "detalle": pruebas,
        "aprobado": all(r["rechazado"] for r in pruebas.values()),
        "aviso": "Todos los intentos deben aparecer rechazados. El servidor impostor con CA "
                 "desconocida se cubre en tools.ataque_opcional; la reconexión del túnel tras "
                 "revocación se verifica en las pruebas manuales con OpenVPN Connect.",
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(documento, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(documento["resumen"], indent=2, ensure_ascii=False))
    print(f"\nEvidencia: {args.json}")
    if not documento["aprobado"]:
        raise SystemExit("FALLO: algún intento no fue rechazado.")
    print("Todos los intentos fueron rechazados por el gateway.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
