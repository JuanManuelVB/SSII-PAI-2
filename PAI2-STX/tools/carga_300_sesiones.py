"""RS3: 300 sesiones de aplicación simultáneas, por HTTPS TLS 1.3/mTLS.

Cada identidad RF5 utiliza su propio certificado, clave y contraseña; se
establecen sesiones independientes y se sincronizan en un intervalo común de
uso de un recurso protegido. No crea túneles VPN ni 300 máquinas virtuales.

No almacena contraseñas, claves privadas ni tokens en el informe JSON.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import ssl
import statistics
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization

from src.rf2.autenticacion import mensaje_a_firmar
from tools.carga_gateway import _contexto, _firmar, _muestra_proc, cargar_identidades


@dataclass
class Resultado:
    estado: str = "pendiente"
    etapa: str = "inicio"
    tiempo_login_ms: float | None = None
    mensajes_correctos: int = 0
    errores_mensajes: int = 0
    latencias_mensaje_ms: list[float] = field(default_factory=list)
    reintentos_auth: int = 0
    respuestas_500_auth: list[str] = field(default_factory=list)
    logout_ok: bool = False
    token_rechazado: bool = False
    motivo: str | None = None


def _percentiles(muestras: list[float]) -> dict:
    vals = sorted(muestras)
    if not vals:
        return {"media": None, "p50": None, "p95": None, "max": None}
    def p(q: float) -> float:
        return round(vals[min(len(vals) - 1, int((len(vals) - 1) * q))], 2)
    return {
        "media": round(statistics.fmean(vals), 2),
        "p50": p(0.50), "p95": p(0.95), "max": round(vals[-1], 2),
    }


def _conexiones_establecidas_al_gateway(puerto: int) -> int | None:
    """Cuenta sockets cliente ESTABLISHED dirigidos al gateway desde WSL.

    En un ensayo local 127.0.0.1:9443 se contabiliza SOLO el extremo cliente
    (dport=9443), no ambos extremos del socket. Puede no estar disponible.
    """
    total = 0
    visto = False
    for archivo in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lineas = Path(archivo).read_text().splitlines()[1:]
        except OSError:
            continue
        visto = True
        for linea in lineas:
            columnas = linea.split()
            if len(columnas) < 4 or columnas[3] != "01":
                continue
            try:
                if int(columnas[2].rsplit(":", 1)[1], 16) == puerto:
                    total += 1
            except (ValueError, IndexError):
                continue
    return total if visto else None


async def ejecutar(url: str, usuarios: int, duracion: int, preparacion: int,
                   intervalo: float, pid: int | None = None,
                   identidades: list[dict] | None = None,
                   concurrencia_auth: int = 6,
                   reintentos_http_500: int = 2) -> dict:
    if usuarios < 1 or usuarios > 300:
        raise ValueError("--usuarios debe estar entre 1 y 300")
    if not 1 <= duracion <= 600:
        raise ValueError("--duracion debe estar entre 1 y 600 segundos")
    if not 5 <= preparacion <= 1200:
        raise ValueError("--preparacion debe estar entre 5 y 1200 segundos")
    if not 0.5 <= intervalo <= 30:
        raise ValueError("--intervalo debe estar entre 0.5 y 30 segundos")
    if not 1 <= concurrencia_auth <= 300:
        raise ValueError("--concurrencia-auth debe estar entre 1 y 300")
    if not 0 <= reintentos_http_500 <= 5:
        raise ValueError("--reintentos-http-500 debe estar entre 0 y 5")
    if not url.startswith("https://"):
        raise ValueError("El gateway debe utilizar HTTPS (TLS/mTLS)")

    pool = identidades if identidades is not None else cargar_identidades()
    if len(pool) < usuarios:
        raise ValueError(
            f"Solo hay {len(pool)} identidades RF5 completas para {usuarios} usuarios. "
            "Necesitas un certificado y contraseña por cada usuario; NO se duplicarán cuentas."
        )
    seleccion = pool[:usuarios]
    if len({i["usuario"] for i in seleccion}) != usuarios or len({i["device_id"] for i in seleccion}) != usuarios:
        raise ValueError("Las identidades no son únicas; la prueba exige usuarios/dispositivos distintos")

    print(f"[RS3] Iniciando {usuarios} clientes mTLS distintos. Preparación máxima: {preparacion}s. "
          f"Autenticaciones simultáneas (admisión): {concurrencia_auth}. "
          f"Reintentos HTTP 500 permitidos: {reintentos_http_500}", flush=True)
    inicio = time.perf_counter()
    resultados = [Resultado() for _ in seleccion]
    comenzar = asyncio.Event()
    # Controla SOLO los handshakes/challenge/login/GET me en fase de preparación.
    # Fuera de este semáforo todas las sesiones siguen activas en la barrera.
    semaforo_login = asyncio.Semaphore(concurrencia_auth)
    cuenta_listos = 0
    inicio_hold: float | None = None
    fin_hold: float | None = None
    # No se guardan claves privadas, contraseñas ni tokens en 'resultados'.
    async def cliente(i: int, ident: dict) -> None:
        nonlocal cuenta_listos
        r = resultados[i]
        token = None
        acceso = None
        try:
            ctx = _contexto(ident["cert"], ident["key"])
            clave = serialization.load_pem_private_key(ident["key"].read_bytes(), password=None)
            cert_pem = ident["cert"].read_text(encoding="ascii")
            # Una instancia AsyncClient y un pool KEEPALIVE por dispositivo.
            limites = httpx.Limits(max_connections=1, max_keepalive_connections=1, keepalive_expiry=None)
            acceso = httpx.AsyncClient(base_url=url, verify=ctx, trust_env=False, limits=limites,
                                       timeout=httpx.Timeout(35.0, connect=15.0))
            # Se escalonan solo los logins. Si el servidor devuelve HTTP 500
            # durante /challenge o /login, se repite la AUTENTICACION COMPLETA:
            # nuevo challenge y nueva firma. Nunca se reutiliza un nonce consumido.
            # Los rechazos 401/403 y los problemas de certificados NO se reintentan.
            r.etapa = "cola_autenticacion"
            for intento in range(reintentos_http_500 + 1):
                error_transitorio = None
                async with semaforo_login:
                    r.etapa = "challenge"
                    reto = await acceso.post("/api/v1/sessions/challenge", json={
                        "username": ident["usuario"], "device_id": ident["device_id"]})
                    if reto.status_code == 500:
                        error_transitorio = "challenge HTTP 500"
                    elif reto.status_code != 200:
                        raise RuntimeError(f"challenge HTTP {reto.status_code}")
                    else:
                        nonce = reto.json()["nonce"]
                        firma = _firmar(clave, mensaje_a_firmar(nonce, ident["usuario"], ident["device_id"]))
                        r.etapa = "login"
                        t0 = time.perf_counter()
                        login = await acceso.post("/api/v1/sessions/login", json={
                            "username": ident["usuario"], "device_id": ident["device_id"],
                            "password": ident["password"], "nonce": nonce,
                            "certificate": cert_pem, "signature": firma,
                        })
                        r.tiempo_login_ms = round((time.perf_counter() - t0) * 1000, 2)
                        if login.status_code == 500:
                            error_transitorio = "login HTTP 500"
                        elif login.status_code != 200:
                            raise RuntimeError(f"login HTTP {login.status_code}")
                        else:
                            token = login.json()["access_token"]
                            cab = {"Authorization": f"Bearer {token}"}
                            r.etapa = "consultar_sesion"
                            me = await acceso.get("/api/v1/sessions/me", headers=cab)
                            if me.status_code != 200 or me.json().get("username") != ident["usuario"]:
                                raise RuntimeError(f"verificación de sesión HTTP {me.status_code}")
                            r.estado = "preparado"
                            r.etapa = "esperando_barrera"
                            cuenta_listos += 1
                if error_transitorio is None:
                    break
                r.respuestas_500_auth.append(error_transitorio)
                if intento == reintentos_http_500:
                    raise RuntimeError(error_transitorio + " (reintentos agotados)")
                r.reintentos_auth += 1
                r.etapa = "espera_reintento"
                await asyncio.sleep(0.35 * (2 ** intento) + (i % 7) * 0.06)

            # Durante la preparación, heartbeat cada ~2s. Evita que el
            # servidor cierre el socket antes del instante de concurrencia.
            while not comenzar.is_set():
                try:
                    await asyncio.wait_for(comenzar.wait(), timeout=min(intervalo, 2.0))
                except asyncio.TimeoutError:
                    vigente = await acceso.get("/api/v1/sessions/me", headers=cab)
                    if vigente.status_code != 200:
                        raise RuntimeError(f"sesión invalidada antes de barrera: HTTP {vigente.status_code}")

            if inicio_hold is None or fin_hold is None:
                return  # Preparación agotada y prueba cancelada.
            r.estado = "en_periodo_comun"
            r.etapa = "comunicacion_cifrada"
            secuencia = 0
            while time.perf_counter() < fin_hold:
                mensaje = f"BYODSEC-RS3-{i:03d}-{secuencia}-{time.monotonic_ns()}"
                enviado = mensaje.encode("utf-8")
                t1 = time.perf_counter()
                respuesta = await acceso.post("/api/v1/resources/echo", headers=cab,
                                             json={"mensaje": mensaje})
                r.latencias_mensaje_ms.append((time.perf_counter() - t1) * 1000)
                correcto = respuesta.status_code == 200
                if correcto:
                    datos = respuesta.json()
                    correcto = (datos.get("sha256") == hashlib.sha256(enviado).hexdigest()
                                and datos.get("bytes") == len(enviado)
                                and datos.get("username") == ident["usuario"])
                if not correcto:
                    r.errores_mensajes += 1
                    raise RuntimeError(f"mensaje rechazado o alterado (HTTP {respuesta.status_code})")
                r.mensajes_correctos += 1
                secuencia += 1
                resto = fin_hold - time.perf_counter()
                if resto > 0:
                    await asyncio.sleep(min(intervalo, resto))
            r.estado = "periodo_completado"
            r.etapa = "logout"
        except asyncio.CancelledError:
            r.estado = "interrumpido"
            r.motivo = "preparacion excedida o cancelación"
            raise
        except (httpx.HTTPError, ssl.SSLError, OSError, ValueError, RuntimeError, KeyError) as exc:
            r.estado = "fallo"
            r.motivo = _categoria_error(exc, r.etapa)
        except Exception as exc:
            r.estado = "fallo"
            r.motivo = f"error inesperado ({type(exc).__name__}, etapa {r.etapa})"
        finally:
            if acceso is not None:
                if token is not None:
                    try:
                        # Los logouts se escalonan AL TERMINAR el periodo común.
                        # 300 sesiones sí han estado activas juntas previamente.
                        async with semaforo_login:
                            cab = {"Authorization": f"Bearer {token}"}
                            resp = await acceso.post("/api/v1/sessions/logout", headers=cab)
                            r.logout_ok = resp.status_code == 200
                            if not r.logout_ok and r.motivo is None:
                                r.motivo = f"logout HTTP {resp.status_code}"
                            if r.logout_ok:
                                otra = await acceso.get("/api/v1/sessions/me", headers=cab)
                                r.token_rechazado = otra.status_code == 401
                                if not r.token_rechazado and r.motivo is None:
                                    r.motivo = f"token no rechazado HTTP {otra.status_code}"
                    except (httpx.HTTPError, OSError, RuntimeError) as exc:
                        if r.motivo is None:
                            r.motivo = f"error al cerrar sesión: {type(exc).__name__}"
                await acceso.aclose()

    def _categoria_error(exc: Exception, etapa: str) -> str:
        if isinstance(exc, httpx.TimeoutException):
            return f"timeout ({etapa})"
        if isinstance(exc, (httpx.ConnectError, ssl.SSLError, OSError)):
            return f"conexión TLS/red ({etapa}): {type(exc).__name__}"
        if isinstance(exc, RuntimeError):
            return str(exc)[:140]
        return f"{type(exc).__name__} ({etapa})"

    tareas = [asyncio.create_task(cliente(i, identificador)) for i, identificador in enumerate(seleccion)]
    rss_pico = 0
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    cpu_ini = _muestra_proc(pid)[0] if pid else 0
    tcp_pico = 0
    t_preparacion = time.perf_counter() + preparacion
    siguiente_aviso = time.perf_counter() + 10
    try:
        while time.perf_counter() < t_preparacion:
            listos = sum(r.estado == "preparado" for r in resultados)
            pendientes = sum(r.estado == "pendiente" for r in resultados)
            if listos == usuarios or not pendientes and listos + sum(r.estado in ("fallo", "interrumpido") for r in resultados) == usuarios:
                break
            if time.perf_counter() >= siguiente_aviso:
                print(f"[RS3] Preparación: {listos}/{usuarios} sesiones válidas; "
                      f"{sum(r.estado == 'fallo' for r in resultados)} fallos", flush=True)
                siguiente_aviso += 10
            if pid:
                rss_pico = max(rss_pico, _muestra_proc(pid)[1])
            await asyncio.sleep(0.25)
        # Cancelamos únicamente usuarios que no han conseguido llegar a la barrera.
        pendientes_tareas = [t for j,t in enumerate(tareas) if resultados[j].estado == "pendiente"]
        for tarea in pendientes_tareas:
            tarea.cancel()
        if pendientes_tareas:
            await asyncio.gather(*pendientes_tareas, return_exceptions=True)
        listos_al_inicio = sum(r.estado == "preparado" for r in resultados)
        inicio_hold = time.perf_counter()
        fin_hold = inicio_hold + duracion
        print(f"[RS3] Barrera: {listos_al_inicio}/{usuarios} sesiones autenticadas. "
              f"Periodo común: {duracion}s", flush=True)
        comenzar.set()
        siguiente_aviso = time.perf_counter() + min(duracion, 10)
        while time.perf_counter() < fin_hold:
            c = _conexiones_establecidas_al_gateway(int(url.rsplit(":", 1)[-1].split("/")[0]))
            if c is not None:
                tcp_pico = max(tcp_pico, c)
            if pid:
                rss_pico = max(rss_pico, _muestra_proc(pid)[1])
            if time.perf_counter() >= siguiente_aviso:
                print(f"[RS3] Periodo común: "
                      f"{sum(r.mensajes_correctos for r in resultados)} mensajes confirmados; "
                      f"pico {tcp_pico} sockets TCP establecidos", flush=True)
                siguiente_aviso += 10
            await asyncio.sleep(0.25)
        await asyncio.gather(*tareas, return_exceptions=True)
    finally:
        comenzar.set()
        for t in tareas:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tareas, return_exceptions=True)

    tiempo_total = time.perf_counter() - inicio
    if pid:
        cpu_fin = _muestra_proc(pid)[0]
        rss_pico = max(rss_pico, _muestra_proc(pid)[1])
    lat_login = [r.tiempo_login_ms for r in resultados if r.tiempo_login_ms is not None]
    lat_mens = [v for r in resultados for v in r.latencias_mensaje_ms]
    errores = Counter(r.motivo for r in resultados if r.motivo)
    mensajes = sum(r.mensajes_correctos for r in resultados)
    completos = sum(r.estado == "periodo_completado" and r.mensajes_correctos > 0 for r in resultados)
    logouts = sum(r.logout_ok for r in resultados)
    rechazos = sum(r.token_rechazado for r in resultados)
    aprobado = (listos_al_inicio == usuarios and completos == usuarios and
                sum(r.errores_mensajes for r in resultados) == 0 and
                logouts == usuarios and rechazos == usuarios)
    documento = {
        "fecha_utc": datetime.now(timezone.utc).isoformat(),
        "tipo": "300_sesiones_aplicacion_TLS13_mTLS_NO_OpenVPN",
        "objetivo_usuarios": usuarios,
        "autenticaciones_en_paralelo_durante_preparacion": concurrencia_auth,
        "reintentos_http_500_maximos_por_identidad": reintentos_http_500,
        "usuarios_que_reintentaron_autenticacion": sum(r.reintentos_auth > 0 for r in resultados),
        "total_reintentos_de_autenticacion": sum(r.reintentos_auth for r in resultados),
        "respuestas_http_500_durante_preparacion": sum(len(r.respuestas_500_auth) for r in resultados),
        "respuestas_http_500_por_etapa": dict(Counter(
            motivo for r in resultados for motivo in r.respuestas_500_auth)),
        "identidades_distintas": len(seleccion),
        "duracion_periodo_comun_s": duracion,
        "preparacion_max_s": preparacion,
        "sesiones_validas_en_barrera": listos_al_inicio,
        "usuarios_completaron_periodo_con_mensajes": completos,
        "mensajes_protegidos_confirmados": mensajes,
        "errores_de_mensajes": sum(r.errores_mensajes for r in resultados),
        "pico_conexiones_tcp_establecidas_gateway": tcp_pico,
        "conexiones_tcp_medidas_en": "extremo cliente WSL hacia puerto gateway; pico muestreado",
        "cierres_sesion_correctos": logouts,
        "tokens_rechazados_tras_logout": rechazos,
        "errores_por_motivo": dict(errores.most_common(12)),
        "latencia_login_ms": _percentiles(lat_login),
        "latencia_mensaje_ms": _percentiles(lat_mens),
        "duracion_total_s": round(tiempo_total, 2),
        "resultado": "APROBADO" if aprobado else "NO_APROBADO",
        "alcance": "Sesiones REST autenticadas y mensajes sobre mTLS en WSL; no túneles IP VPN",
        "nota": "300 sesiones autenticadas NO prueban 300 ordenadores físicos ni 300 VPN."
    }
    if pid:
        doc_cpu = (_muestra_proc(pid)[0] - cpu_ini) / hz
        documento["gateway_cpu_s"] = round(doc_cpu, 2)
        documento["gateway_cpu_pct_promedio"] = round(100 * doc_cpu / tiempo_total, 2)
        documento["gateway_ram_pico_mb"] = round(rss_pico / 1024, 2)
    return documento


def main() -> int:
    p = argparse.ArgumentParser(description="RS3: hasta 300 sesiones simultáneas TLS 1.3/mTLS reales")
    p.add_argument("--usuarios", type=int, default=300, help="Cuentas distintas (no se repiten)")
    p.add_argument("--duracion", type=int, default=30, help="Segundos del periodo común con mensajes")
    p.add_argument("--preparacion", type=int, default=240, help="Máximo para autenticar a todos")
    p.add_argument("--intervalo", type=float, default=2.5, help="Segundos entre mensajes por sesión")
    p.add_argument("--url", default="https://localhost:9443")
    p.add_argument("--concurrencia-auth", type=int, default=6,
                   help="Máximo de logins simultáneos durante preparación, no limita las sesiones activas")
    p.add_argument("--reintentos-http-500", type=int, default=2,
                   help="Reintenta challenge+login con nuevo nonce ante HTTP 500; registra todos los fallos")
    p.add_argument("--pid", type=int, help="PID de uvicorn gateway para CPU/RAM")
    p.add_argument("--json", type=Path, default=Path("bench/resultados/300_sesiones_mtls.json"))
    args = p.parse_args()
    try:
        resultado = asyncio.run(ejecutar(args.url, args.usuarios, args.duracion,
                                        args.preparacion, args.intervalo, args.pid,
                                        concurrencia_auth=args.concurrencia_auth,
                                        reintentos_http_500=args.reintentos_http_500))
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}")
        return 2
    salida = json.dumps(resultado, indent=2, ensure_ascii=False)
    print(salida)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(salida + "\n", encoding="utf-8")
        print(f"[RS3] Informe: {args.json}")
    return 0 if resultado["resultado"] == "APROBADO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
