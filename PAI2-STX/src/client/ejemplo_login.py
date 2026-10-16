"""Cliente demostrador de RF2 y RF4 usando mTLS y una firma de desafío.

Uso: python -m src.client.ejemplo_login --username rf5_inv_001 \
    --device-id rf5-inv-001-dev01 \
    --cert pki/clients/rf5/rf5_inv_001.crt \
    --key pki/clients/rf5/rf5_inv_001.key

La contraseña se pide de forma interactiva y nunca aparece en argumentos.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import ssl
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from src.rf2.autenticacion import mensaje_a_firmar


def main() -> None:
    parser = argparse.ArgumentParser(description="Prueba integral RF2 → RF4")
    parser.add_argument("--username", required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--ca", type=Path, default=Path("pki/ca/ca.crt"))
    parser.add_argument("--url", default="https://localhost:8443")
    args = parser.parse_args()

    password = getpass.getpass("Contraseña: ")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cafile=str(args.ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(args.cert), str(args.key))
    clave = serialization.load_pem_private_key(args.key.read_bytes(), password=None)

    with httpx.Client(verify=context, base_url=args.url, timeout=10.0) as client:
        desafio = client.post("/api/v1/sessions/challenge", json={
            "username": args.username, "device_id": args.device_id,
        })
        desafio.raise_for_status()
        nonce = desafio.json()["nonce"]
        mensaje = mensaje_a_firmar(nonce, args.username, args.device_id)
        if isinstance(clave, rsa.RSAPrivateKey):
            firma = clave.sign(mensaje, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(clave, ec.EllipticCurvePrivateKey):
            firma = clave.sign(mensaje, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError("Tipo de clave no admitido")

        respuesta = client.post("/api/v1/sessions/login", json={
            "username": args.username,
            "device_id": args.device_id,
            "password": password,
            "nonce": nonce,
            "certificate": args.cert.read_text(encoding="ascii"),
            "signature": base64.b64encode(firma).decode("ascii"),
        })
        respuesta.raise_for_status()
        token = respuesta.json()["access_token"]
        cabeceras = {"Authorization": "Bearer " + token}
        print("RF2 login:", respuesta.status_code)
        consulta = client.get("/api/v1/sessions/me", headers=cabeceras)
        consulta.raise_for_status()
        print("RF2 me:", consulta.json())
        cierre = client.post("/api/v1/sessions/logout", headers=cabeceras)
        cierre.raise_for_status()
        print("RF4 logout:", cierre.json())
        posterior = client.get("/api/v1/sessions/me", headers=cabeceras)
        print("RF4 token revocado, acceso posterior:", posterior.status_code)
        if posterior.status_code != 401:
            raise RuntimeError("ERROR: el token siguió siendo válido tras logout")
    # El contexto del cliente cierra aquí sus sockets TLS.


if __name__ == "__main__":
    main()
