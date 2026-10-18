"""Prueba extremo a extremo contra los servicios REALES del laboratorio.

Recorre RF1 → RF2 → VPN → RF4 por HTTPS/TLS 1.3/mTLS, igual que lo haría la
consola, y guarda el resultado de cada paso (sin contraseñas ni tokens) en
``evidencias/logs/e2e_laboratorio.json``.

Requiere los servicios en marcha (bash laboratorio.sh arrancar). Con
``BYODSEC_VPN_REST=1`` cada login autoriza además la cuenta en Access Server
y cada logout la bloquea, desconecta y verifica por REST.

Uso: python -m tools.prueba_e2e_laboratorio
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.client.servicio_consola import (
    CA_DEFECTO, DIR_CLIENTES, ClienteConsola, ErrorConsola, IdentidadLocal,
    contexto_cliente, registrar_dispositivo,
)

RAIZ = Path(__file__).resolve().parents[1]
CREDENCIALES = RAIZ / "pki" / "clients" / "rf5" / "credenciales.csv"
USUARIO = "rf5_inv_001"
DISPOSITIVO_RF5 = "rf5-inv-001-dev01"
DISPOSITIVO_RF1 = "e2e-inv-001-dev02"


class Registro:
    def __init__(self) -> None:
        self.pasos: list[dict] = []

    def paso(self, requisito: str, nombre: str, esperado: str, accion: Callable[[], str]) -> None:
        try:
            obtenido = accion()
            correcto = True
        except Exception as exc:  # noqa: BLE001 - se registra el fallo y se sigue
            obtenido = f"{type(exc).__name__}: {exc}"
            correcto = False
        self.pasos.append({"requisito": requisito, "paso": nombre, "esperado": esperado,
                           "obtenido": obtenido, "resultado": "PASS" if correcto else "FAIL"})
        print(f"  [{'PASS' if correcto else 'FAIL'}] {requisito:<4} {nombre}: {obtenido}")


def _password(usuario: str) -> str:
    with CREDENCIALES.open(encoding="utf-8", newline="") as archivo:
        for fila in csv.DictReader(archivo):
            if fila["username"] == usuario:
                return fila["password"]
    raise LookupError(f"No hay credencial local para {usuario}")


def _exigir(condicion: bool, mensaje: str) -> None:
    if not condicion:
        raise AssertionError(mensaje)


def ejecutar(url: str, url_registro: str, vpn: bool) -> dict:
    registro = Registro()
    password = _password(USUARIO)
    rf5 = IdentidadLocal(USUARIO, DISPOSITIVO_RF5, DIR_CLIENTES / "rf5" / f"{USUARIO}.crt",
                         DIR_CLIENTES / "rf5" / f"{USUARIO}.key")
    rf1 = IdentidadLocal(USUARIO, DISPOSITIVO_RF1, DIR_CLIENTES / f"{DISPOSITIVO_RF1}.crt",
                         DIR_CLIENTES / f"{DISPOSITIVO_RF1}.key")

    # ------------------------------------------------------------- RF1
    def alta_rf1() -> str:
        if rf1.certificado.is_file() and rf1.clave.is_file():
            return "dispositivo ya emparejado en una ejecución anterior (se reutiliza)"
        registrar_dispositivo(usuario=USUARIO, password=password, device_id=DISPOSITIVO_RF1,
                              url_registro=url_registro)
        return "HTTP 201, certificado emitido para una clave generada en el cliente"

    def registrar_crudo(device_id: str, clave_pwd: str) -> int:
        clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        publica = clave.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        with httpx.Client(verify=contexto_cliente(CA_DEFECTO), base_url=url_registro,
                          timeout=20, trust_env=False) as cliente:
            return cliente.post("/api/v1/devices/register", json={
                "username": USUARIO, "password": clave_pwd, "device_id": device_id,
                "public_key": publica}).status_code

    def rf1_duplicado() -> str:
        codigo = registrar_crudo(DISPOSITIVO_RF1, password)
        _exigir(codigo == 409, f"HTTP {codigo}")
        return "HTTP 409"

    def rf1_credenciales() -> str:
        codigo = registrar_crudo("e2e-no-autorizado", "contrasena-incorrecta-123")
        _exigir(codigo == 401, f"HTTP {codigo}")
        return "HTTP 401"

    registro.paso("RF1", "alta de un dispositivo nuevo", "HTTP 201", alta_rf1)
    registro.paso("RF1", "rechazo de device_id ya emparejado", "HTTP 409", rf1_duplicado)
    registro.paso("RF1", "rechazo de credenciales incorrectas", "HTTP 401", rf1_credenciales)

    # ------------------------------------------------- RF2 + VPN + RF4
    principal = ClienteConsola(url=url)

    def login_rf5() -> str:
        datos = principal.iniciar_sesion(rf5, password)
        return f"HTTP {datos['codigo']}" + (" + VPN autorizada por REST" if vpn else "")

    def me() -> str:
        datos = principal.consultar_sesion()
        _exigir(datos["username"] == USUARIO, "usuario distinto")
        return f"HTTP 200, rol {datos['role']}"

    def vpn_me() -> str:
        datos = principal.consultar_vpn()
        return f"HTTP 200, túneles activos del usuario: {datos.get('count', 0)}"

    def segundo_dispositivo() -> str:
        otro = ClienteConsola(url=url)
        try:
            otro.iniciar_sesion(rf1, password)
        except ErrorConsola as exc:
            _exigir("409" in str(exc), str(exc))
            return "HTTP 409, la cuenta VPN ya está en uso por otro dispositivo"
        otro.desconectar_local()
        raise AssertionError("se autorizó un segundo dispositivo simultáneo")

    def logout(cliente: ClienteConsola) -> Callable[[], str]:
        def accion() -> str:
            resultado = cliente.cerrar_sesion(comprobar_revocacion=True)
            _exigir(resultado.rechazo_comprobado is True,
                    f"token anterior devolvió HTTP {resultado.codigo_comprobacion}")
            return "HTTP 200 y token anterior rechazado con HTTP 401" + (
                " (VPN bloqueada y desconexión verificada por REST)" if vpn else "")
        return accion

    registro.paso("RF2", "login mTLS + contraseña + desafío firmado (RF5)", "HTTP 200", login_rf5)
    registro.paso("RF2", "consulta de sesión /me", "HTTP 200", me)
    if vpn:
        registro.paso("VPN", "estado VPN propio por REST", "HTTP 200", vpn_me)
        registro.paso("VPN", "segundo dispositivo con la cuenta en uso", "HTTP 409", segundo_dispositivo)
    registro.paso("RF4", "logout + reutilización del token", "HTTP 200 / 401", logout(principal))

    secundario = ClienteConsola(url=url)
    registro.paso("RF2", "login con el dispositivo emparejado por RF1", "HTTP 200",
                  lambda: f"HTTP {secundario.iniciar_sesion(rf1, password)['codigo']}")
    registro.paso("RF4", "logout del dispositivo RF1", "HTTP 200 / 401", logout(secundario))

    def password_incorrecta() -> str:
        try:
            ClienteConsola(url=url).iniciar_sesion(rf5, "contrasena-incorrecta-123")
        except ErrorConsola as exc:
            _exigir("401" in str(exc), str(exc))
            return "HTTP 401"
        raise AssertionError("login aceptado con contraseña incorrecta")

    def sin_certificado() -> str:
        try:
            with httpx.Client(verify=contexto_cliente(CA_DEFECTO), base_url=url,
                              timeout=10, trust_env=False) as cliente:
                codigo = cliente.post("/api/v1/sessions/challenge", json={
                    "username": USUARIO, "device_id": DISPOSITIVO_RF5}).status_code
        except httpx.TransportError as exc:
            return f"conexión TLS rechazada ({type(exc).__name__})"
        _exigir(codigo == 403, f"HTTP {codigo}")
        return "HTTP 403"

    registro.paso("RF2", "rechazo de contraseña incorrecta", "HTTP 401", password_incorrecta)
    registro.paso("RS1", "rechazo de cliente sin certificado mTLS", "rechazo", sin_certificado)

    return {"fecha_utc": datetime.now(timezone.utc).isoformat(), "gateway": url,
            "registro_rf1": url_registro, "modo_vpn_rest": vpn, "pasos": registro.pasos,
            "aprobado": all(p["resultado"] == "PASS" for p in registro.pasos)}


def main() -> int:
    parser = argparse.ArgumentParser(description="E2E RF1→RF2→VPN→RF4 contra el laboratorio en marcha")
    parser.add_argument("--url", default="https://localhost:9443")
    parser.add_argument("--registro-url", default="https://localhost:8444")
    parser.add_argument("--json", type=Path, default=RAIZ / "evidencias" / "logs" / "e2e_laboratorio.json")
    args = parser.parse_args()
    documento = ejecutar(args.url, args.registro_url, os.environ.get("BYODSEC_VPN_REST") == "1")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(documento, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Resultado: {'APROBADO' if documento['aprobado'] else 'CON FALLOS'} -> {args.json}")
    return 0 if documento["aprobado"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
