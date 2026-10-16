"""Autenticación del canal REST interno. No sustituye mTLS del gateway BYODSEC."""
from __future__ import annotations

import hmac
import os
from pathlib import Path
from fastapi import Header, HTTPException


def leer_token() -> str:
    # La clave se mantiene fuera del código y del repositorio.
    secret_file = os.environ.get('BYODSEC_VPN_API_TOKEN_FILE')
    if not secret_file:
        raise RuntimeError('Definir BYODSEC_VPN_API_TOKEN_FILE con una clave privada')
    p = Path(secret_file)
    if not p.is_file():
        raise RuntimeError('Archivo de clave REST interna no encontrado')
    token = p.read_text(encoding='ascii').strip()
    if len(token) < 40:
        raise RuntimeError('Clave de servicio demasiado corta')
    return token


def exigir_servicio(authorization: str | None = Header(default=None)) -> None:
    # Todos los endpoints de este microservicio exigen la misma credencial.
    expected = leer_token()
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Credencial de servicio requerida')
    supplied = authorization[7:]
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail='Credencial de servicio incorrecta')
