"""Descarga por REST HTTPS un perfil individual (no autologin) al WSL privado."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import httpx
from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer, AccessServerError


def generar(destino: Path, username: str = "rf5_inv_001") -> None:
    api = AccessServerClient(ConfigAccessServer.desde_entorno())
    with api._cliente() as cli:
        login = cli.post("/api/auth/login/userpassword", json={
            "username": api.config.username,
            "password": api.config.password,
            "request_admin": True,
        })
        login.raise_for_status()
        token = login.json().get("auth_token")
        if not isinstance(token, str) or not token:
            raise AccessServerError("No se ha recibido token de la API REST")
        respuesta = cli.post("/api/profiles/create", json={
            "username": username,
            "profile_type": "userlogin",
            "tls_crypt_v2": True,
            "comment": "BYODSEC laboratorio local",
        }, headers={"X-OpenVPN-As-AuthToken": token})
        respuesta.raise_for_status()
        data = respuesta.content
        # La API devuelve el contenido del perfil; nunca aceptar una respuesta
        # JSON de error y guardarla como perfil funcional.
        if not data or b"<ca>" not in data or b"remote " not in data:
            raise AccessServerError("Respuesta de perfil no reconocida; revisar Swagger /profiles/create")
        destino.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--destino", type=Path, required=True)
    args=p.parse_args()
    try:
        generar(args.destino)
    except (AccessServerError, httpx.HTTPError, OSError) as e:
        p.exit(1, f"No se pudo descargar el perfil VPN por REST: {type(e).__name__}: {e}\n")

if __name__ == "__main__":
    main()
