"""RS3: comparar mensajes reales HTTPS/TLS1.3/mTLS contra HTTP local sin cifrar.

Uso desde la raíz del proyecto, servidor BYODSEC levantado:
  .venv-wsl/bin/python -m tools.comparativa_cifrado --usuarios 10 --mensajes 20 --bytes 256

Crea/retira automáticamente una línea base HTTP en loopback. Autentica N
identidades RF5 distintas ANTES de medir. Usa N clientes persistentes por
escenario, mismo número de mensajes y misma carga útil. Los tiempos medidos
excluyen login, pero en HTTPS incluyen la validación del token/identidad que
no se hace en HTTP: NO atribuir toda la diferencia exclusivamente al cifrado.

NO mide un túnel IP VPN. NO guarda contraseñas, tokens, claves ni mensajes.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import ssl
import statistics
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization

from src.rf2.autenticacion import mensaje_a_firmar
from tools.carga_gateway import _contexto, _firmar, _muestra_proc, cargar_identidades

RAIZ = Path(__file__).resolve().parents[1]


def estadisticas(valores: list[float]) -> dict[str, float | None]:
    if not valores:
        return {"media": None, "p50": None, "p95": None, "max": None}
    lista = sorted(valores)
    def percentil(p: float) -> float:
        return round(lista[min(len(lista) - 1, int((len(lista) - 1) * p))], 3)
    return {"media": round(statistics.fmean(lista), 3), "p50": percentil(.5),
            "p95": percentil(.95), "max": round(lista[-1], 3)}


def sobrecostes(tls: dict, http: dict) -> dict | None:
    # Una métrica a cero por fallos no se convierte en un falso -100%.
    if not (tls["errores"] == 0 and http["errores"] == 0 and
            tls["mensajes_confirmados"] == http["mensajes_confirmados"] > 0):
        return None
    l_tls = tls["latencia_mensaje_ms"]["media"]
    l_http = http["latencia_mensaje_ms"]["media"]
    t_tls = tls["throughput_mensajes_por_s"]
    t_http = http["throughput_mensajes_por_s"]
    if not l_http or not t_http:
        return None
    return {
        "incremento_latencia_media_pct": round(100 * (l_tls / l_http - 1), 2),
        "perdida_throughput_pct": round(100 * (1 - t_tls / t_http), 2),
    }


def payload(identidad: int, secuencia: int, tamano: int) -> str:
    prefijo = f"RS3-{identidad:03d}-{secuencia:05d}-"
    # Datos sintéticos ASCII; longitud UTF-8 exactamente solicitada.
    return (prefijo + "X" * tamano)[:tamano]


@asynccontextmanager
async def servidor_http_local(puerto: int, espera_arranque_s: float = 60.0):
    """Inicia HTTP local, espera a que esté listo y guarda los errores de arranque.

    En equipos WSL2 con el proyecto bajo /mnt/c/ (especialmente OneDrive),
    ocho segundos pueden no bastar para cargar Python, FastAPI y Uvicorn.
    """
    url = f"http://127.0.0.1:{puerto}"
    async with httpx.AsyncClient(trust_env=False, timeout=2.0) as cliente:
        try:
            previo = await cliente.get(url + "/health")
        except httpx.TransportError:
            previo = None
        if previo is not None:
            raise RuntimeError(
                f"Puerto {puerto} ocupado: detén el otro servicio HTTP "
                "(esta herramienta arranca y detiene su propio servidor local)"
            )

    ruta_log = RAIZ / "evidencias" / "logs" / "rs3_http_local_arranque.log"
    ruta_log.parent.mkdir(parents=True, exist_ok=True)
    with ruta_log.open("w", encoding="utf-8") as salida:
        proceso = subprocess.Popen(
            [sys.executable, "-m", "tools.servidor_sin_cifrar",
             "--host", "127.0.0.1", "--port", str(puerto)],
            cwd=RAIZ, stdout=salida, stderr=subprocess.STDOUT,
        )
        print(f"[RS3] Iniciando HTTP sin cifrar en {url}; "
              f"espera máxima {espera_arranque_s:g}s", flush=True)
        try:
            inicio = time.monotonic()
            async with httpx.AsyncClient(trust_env=False, timeout=2.0) as cliente:
                while time.monotonic() - inicio < espera_arranque_s:
                    if proceso.poll() is not None:
                        salida.flush()
                        detalle = ruta_log.read_text(encoding="utf-8", errors="replace")[-1200:]
                        raise RuntimeError(
                            f"Servidor HTTP 9080 terminó (código {proceso.returncode}). "
                            f"Consulta {ruta_log}. Detalles: {detalle or 'sin salida'}"
                        )
                    try:
                        respuesta = await cliente.get(url + "/health")
                        if (respuesta.status_code == 200 and
                                respuesta.json().get("servicio") == "byodsec_rs3_http_sin_cifrar"):
                            print("[RS3] Línea base HTTP lista; iniciando la preparación.", flush=True)
                            break
                    except (httpx.HTTPError, ValueError):
                        pass
                    await asyncio.sleep(0.25)
                else:
                    salida.flush()
                    detalle = ruta_log.read_text(encoding="utf-8", errors="replace")[-1200:]
                    raise RuntimeError(
                        f"La línea base HTTP no respondió en {espera_arranque_s:g} segundos "
                        f"(puerto {puerto}). Revisa {ruta_log}. "
                        f"Salida: {detalle or 'sin mensajes: comprobar WSL y el intérprete Python'}"
                    )
            yield url, proceso.pid
        finally:
            if proceso.poll() is None:
                proceso.terminate()
                try:
                    proceso.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proceso.kill()
                    proceso.wait(timeout=3)


async def comprobar_gateway_tls(url_tls: str, identidad: dict) -> None:
    """Confirma el puerto real, TLS 1.3 y el certificado mTLS antes del ensayo.

    Se conecta únicamente al loopback de WSL. No autentica sesiones, no
    transmite contraseñas y no cuenta como parte de la medición RS3.
    """
    parsed = urlsplit(url_tls)
    puerto = parsed.port or 443
    servidor = parsed.hostname or "localhost"
    print(f"[RS3] Comprobando gateway HTTPS/mTLS en {servidor}:{puerto}...", flush=True)
    contexto = _contexto(identidad["cert"], identidad["key"])
    try:
        conexion = asyncio.open_connection(
            host="127.0.0.1", port=puerto, ssl=contexto, server_hostname=servidor
        )
        _lector, escritor = await asyncio.wait_for(conexion, timeout=8)
    except ConnectionRefusedError as exc:
        raise RuntimeError(
            f"El gateway HTTPS/mTLS no escucha en 127.0.0.1:{puerto} de WSL. "
            "Arranca INICIAR_SERVIDOR_BYODSEC.cmd y comprueba que permanezca abierto "
            "sin errores; vuelve a ejecutar la opción 15."
        ) from exc
    except (ssl.SSLError, ConnectionResetError) as exc:
        raise RuntimeError(
            f"Hay un problema de handshake TLS/mTLS con el gateway :{puerto}: "
            f"{type(exc).__name__}: {exc}. Revisa el servidor, CA y certificados RF5."
        ) from exc
    except (OSError, TimeoutError) as exc:
        raise RuntimeError(
            f"No se pudo conectar por TLS al gateway :{puerto}: "
            f"{type(exc).__name__}: {exc}. Verifica el puerto 9443 y los logs del servidor."
        ) from exc
    try:
        tls = escritor.get_extra_info("ssl_object")
        if tls is None or tls.version() != "TLSv1.3":
            raise RuntimeError("El gateway no negoció TLS 1.3; no se realizará la comparativa")
        print(f"[RS3] Gateway listo: TLS 1.3 y certificado de cliente aceptado.", flush=True)
    finally:
        escritor.close()
        try:
            await asyncio.wait_for(escritor.wait_closed(), timeout=2)
        except (OSError, ssl.SSLError, TimeoutError):
            pass


async def autenticar(cli: httpx.AsyncClient, ident: dict) -> str:
    clave = serialization.load_pem_private_key(ident["key"].read_bytes(), password=None)
    solicitud = {"username": ident["usuario"], "device_id": ident["device_id"]}
    try:
        reto = await cli.post("/api/v1/sessions/challenge", json=solicitud)
    except httpx.RequestError as exc:
        raise RuntimeError(
            f"Error en challenge HTTPS (:9443): {type(exc).__name__}: {exc}; "
            "verifica que el gateway continúe activo."
        ) from exc
    if reto.status_code != 200:
        raise RuntimeError(f"RF2 challenge devolvió HTTP {reto.status_code}")
    firma = _firmar(clave, mensaje_a_firmar(reto.json()["nonce"], ident["usuario"], ident["device_id"]))
    try:
        respuesta = await cli.post("/api/v1/sessions/login", json={
            **solicitud, "password": ident["password"], "nonce": reto.json()["nonce"],
            "certificate": ident["cert"].read_text(encoding="ascii"), "signature": firma,
        })
    except httpx.RequestError as exc:
        raise RuntimeError(
            f"Error en login HTTPS (:9443): {type(exc).__name__}: {exc}"
        ) from exc
    if respuesta.status_code != 200:
        raise RuntimeError(f"RF2 login devolvió HTTP {respuesta.status_code}")
    token = respuesta.json()["access_token"]
    try:
        verificacion = await cli.get("/api/v1/sessions/me", headers={"Authorization": f"Bearer {token}"})
    except httpx.RequestError as exc:
        raise RuntimeError(
            f"Error al comprobar sesión HTTPS /me (:9443): {type(exc).__name__}: {exc}"
        ) from exc
    if verificacion.status_code != 200 or verificacion.json().get("username") != ident["usuario"]:
        raise RuntimeError("La sesión mTLS no se pudo verificar")
    return token


async def ejecutar_escenario(nombre: str, clientes: list[httpx.AsyncClient],
                            tokens: list[str], usuarios: int, mensajes: int,
                            tamano: int, pid: int | None) -> dict:
    latencias: list[float] = []
    errores: list[str] = []
    confirmados = 0
    barrera = asyncio.Event()

    async def trabajador(indice: int, cliente: httpx.AsyncClient):
        nonlocal confirmados
        cab = {"Authorization": f"Bearer {tokens[indice]}"} if nombre == "cifrado_tls13_mtls" else {}
        ruta = "/api/v1/resources/echo" if cab else "/echo"
        await barrera.wait()
        for secuencia in range(mensajes):
            mensaje = payload(indice, secuencia, tamano)
            t0 = time.perf_counter()
            try:
                respuesta = await cliente.post(ruta, json={"mensaje": mensaje}, headers=cab)
                delta = (time.perf_counter() - t0) * 1000
                if respuesta.status_code != 200:
                    raise RuntimeError(f"HTTP {respuesta.status_code}")
                datos = respuesta.json()
                if not (datos.get("status") == "processed" and
                        datos.get("bytes") == len(mensaje.encode("utf-8")) and
                        datos.get("sha256") == hashlib.sha256(mensaje.encode("utf-8")).hexdigest()):
                    raise RuntimeError("Integridad de mensaje no verificada")
                latencias.append(delta)
                confirmados += 1
            except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                errores.append(f"usuario {indice + 1}, mensaje {secuencia + 1}: {type(exc).__name__}: {str(exc)[:100]}")
                break  # no confundir éxitos con reintentos ni ocultar errores

    tareas = [asyncio.create_task(trabajador(i, cli)) for i, cli in enumerate(clientes)]
    ticks0 = _muestra_proc(pid)[0] if pid else 0
    ram_pico_kb = 0
    t0 = time.perf_counter()
    barrera.set()
    while not all(t.done() for t in tareas):
        if pid:
            ram_pico_kb = max(ram_pico_kb, _muestra_proc(pid)[1])
        await asyncio.sleep(.04)
    await asyncio.gather(*tareas)
    duracion = time.perf_counter() - t0
    if pid:
        ram_pico_kb = max(ram_pico_kb, _muestra_proc(pid)[1])
    ticks1 = _muestra_proc(pid)[0] if pid else 0
    cpu_s = ((ticks1 - ticks0) / os.sysconf("SC_CLK_TCK")) if pid and ticks1 >= ticks0 else None
    return {
        "mensajes_solicitados": usuarios * mensajes,
        "mensajes_confirmados": confirmados,
        "errores": len(errores), "muestra_errores": errores[:10],
        "duracion_envio_s": round(duracion, 3),
        "throughput_mensajes_por_s": round(confirmados / duracion, 3) if duracion > 0 else None,
        "latencia_mensaje_ms": estadisticas(latencias),
        "cpu_s": round(cpu_s, 3) if cpu_s is not None else None,
        "cpu_pct_medio_1_nucleo": round(100 * cpu_s / duracion, 2) if cpu_s is not None and duracion else None,
        "ram_pico_mb": round(ram_pico_kb / 1024, 2) if pid and ram_pico_kb else None,
    }


async def comparar(usuarios: int, mensajes: int, tamano: int, repeticiones: int,
                  url_tls: str = "https://localhost:9443", puerto_http: int = 9080,
                  pid_tls: int | None = None, espera_http: float = 60.0) -> dict:
    if not url_tls.startswith("https://localhost:") and not url_tls.startswith("https://127.0.0.1:"):
        raise ValueError("La prueba está restringida al gateway HTTPS local")
    if not 1 <= usuarios <= 300 or not 1 <= mensajes <= 200 or not 1 <= tamano <= 2048 or not 1 <= repeticiones <= 5:
        raise ValueError("Límites: 1..300 usuarios, 1..200 mensajes, 1..2048 bytes, 1..5 repeticiones")
    if not 5 <= espera_http <= 180:
        raise ValueError("La espera del servidor HTTP debe estar entre 5 y 180 segundos")
    if not 1024 <= puerto_http <= 65535 or puerto_http == 9443:
        raise ValueError("Puerto HTTP fuera de rango o coincide con el gateway")
    identidades = cargar_identidades()
    if len(identidades) < usuarios:
        raise RuntimeError(f"Solo hay {len(identidades)} cuentas RF5 completas; necesitas {usuarios}")
    identidades = identidades[:usuarios]
    if len({x["usuario"] for x in identidades}) != usuarios:
        raise RuntimeError("No hay N usuarios RF5 distintos")

    # Diagnóstico previo para que el usuario no confunda un gateway caído
    # con una línea base HTTP fallida ni con un problema de 300 usuarios.
    await comprobar_gateway_tls(url_tls, identidades[0])

    # Uvicorn cierra por defecto los sockets HTTP/1.1 tras 5 s de inactividad.
    # No conservar indefinidamente sockets en httpx: expirar ANTES de ese límite
    # evita reutilizar conexiones que el servidor está cerrando.
    # Mismo ajuste en ambos escenarios TLS y HTTP (benchmark comparable).
    limite = httpx.Limits(max_connections=1, max_keepalive_connections=1, keepalive_expiry=2.0)
    tls: list[httpx.AsyncClient] = []
    http: list[httpx.AsyncClient] = []
    sesiones: list[tuple[httpx.AsyncClient, str]] = []
    preparados = 0
    cierres_confirmados = 0
    errores_cierre = 0
    corridas: list[dict] = []
    print(f"[RS3] {usuarios} usuarios, {mensajes} mensajes de {tamano} bytes por usuario y escenario.", flush=True)
    try:
        async with servidor_http_local(puerto_http, espera_http) as (url_http, pid_http):
            sem = asyncio.Semaphore(6)
            async def preparar(i: int, ident: dict):
                nonlocal preparados
                async with sem:
                    c = httpx.AsyncClient(base_url=url_tls, verify=_contexto(ident["cert"], ident["key"]),
                                          trust_env=False, timeout=httpx.Timeout(35., connect=15.), limits=limite)
                    # Registrar de inmediato para cerrar incluso si falla el login.
                    tls.append(c)
                    token = await autenticar(c, ident)
                    sesiones.append((c, token))
                    preparados += 1
                    if preparados % 20 == 0 or preparados == usuarios:
                        print(f"[RS3] Sesiones preparadas: {preparados}/{usuarios}", flush=True)
                    h = httpx.AsyncClient(base_url=url_http, trust_env=False,
                                          timeout=httpx.Timeout(35., connect=15.), limits=limite)
                    http.append(h)
                    # Evitar índices alterados por el orden de terminación de tareas.
                    return (i, c, h, token)

            tareas_preparacion = [asyncio.create_task(preparar(i, ident)) for i, ident in enumerate(identidades)]
            try:
                pares = await asyncio.gather(*tareas_preparacion)
            except BaseException:
                for tarea in tareas_preparacion:
                    tarea.cancel()
                await asyncio.gather(*tareas_preparacion, return_exceptions=True)
                raise
            pares.sort(key=lambda t: t[0])
            tls_ordenado = [p[1] for p in pares]
            http_ordenado = [p[2] for p in pares]
            tokens_ordenados = [p[3] for p in pares]
            # Warm-up simétrico previo y CONCURRENTE (con límite de preparación):
            # la versión secuencial calentaba primero al usuario 1 y tardaba
            # demasiado en llegar al 300. Uvicorn podía cerrar las conexiones
            # antiguas antes de empezar la medición.
            sem_calentar = asyncio.Semaphore(30)

            async def calentar(i: int) -> None:
                async with sem_calentar:
                    datos = payload(i, -1, tamano)
                    try:
                        r1 = await tls_ordenado[i].post(
                            "/api/v1/resources/echo", json={"mensaje": datos},
                            headers={"Authorization": f"Bearer {tokens_ordenados[i]}"})
                        r2 = await http_ordenado[i].post("/echo", json={"mensaje": datos})
                    except httpx.HTTPError as exc:
                        raise RuntimeError(
                            f"Warm-up usuario {i + 1}: {type(exc).__name__}: {exc}"
                        ) from exc
                    if r1.status_code != 200 or r2.status_code != 200:
                        raise RuntimeError(
                            f"Warm-up usuario {i + 1}: TLS HTTP {r1.status_code}; "
                            f"claro HTTP {r2.status_code}"
                        )

            await asyncio.gather(*(calentar(i) for i in range(usuarios)))
            print("[RS3] Preparación/warm-up OK; comenzando mediciones (sin login).", flush=True)

            for vuelta in range(repeticiones):
                orden = ["cifrado_tls13_mtls", "directo_sin_cifrar"]
                if vuelta % 2:
                    orden.reverse()
                resultados = {}
                for escenario in orden:
                    c = tls_ordenado if escenario == "cifrado_tls13_mtls" else http_ordenado
                    resultado = await ejecutar_escenario(
                        escenario, c, tokens_ordenados, usuarios, mensajes, tamano,
                        pid_tls if escenario == "cifrado_tls13_mtls" else pid_http)
                    resultados[escenario] = resultado
                    print(f"[RS3] Repetición {vuelta + 1}/{repeticiones}, {escenario}: "
                          f"{resultado['mensajes_confirmados']}/{resultado['mensajes_solicitados']} "
                          f"mensajes, {resultado['errores']} errores; "
                          f"{resultado['throughput_mensajes_por_s']} msg/s", flush=True)
                corridas.append({"repeticion": vuelta + 1, "orden": orden, "escenarios": resultados,
                                 "sobrecoste": sobrecostes(resultados["cifrado_tls13_mtls"], resultados["directo_sin_cifrar"])})
    finally:
        # No contamos el logout en latencia/throughput. Reportamos fallos de limpieza.
        for c, token in sesiones:
            try:
                r = await c.post("/api/v1/sessions/logout", headers={"Authorization": f"Bearer {token}"})
                if r.status_code == 200:
                    cierres_confirmados += 1
                else:
                    errores_cierre += 1
            except (httpx.HTTPError, OSError):
                errores_cierre += 1
        await asyncio.gather(*(c.aclose() for c in tls + http), return_exceptions=True)

    todos_ok = all(all(r["errores"] == 0 and r["mensajes_confirmados"] == usuarios * mensajes
                         for r in vuelta["escenarios"].values()) for vuelta in corridas)
    return {
        "fecha_utc": datetime.now(timezone.utc).isoformat(),
        "tipo": "RS3_comparativa_mensajes_TLS13_mTLS_vs_HTTP_local_NO_VPN_IP",
        "usuarios": usuarios, "mensajes_por_usuario_y_escenario": mensajes,
        "bytes_por_mensaje": tamano, "repeticiones": repeticiones,
        "autenticaciones_previas": usuarios, "autenticacion_fuera_del_periodo_medido": True,
        "corridas": corridas,
        "cierres_sesion_confirmados_fuera_de_medicion": cierres_confirmados,
        "errores_cierre_fuera_de_medicion": errores_cierre,
        "resultado": "APROBADO" if todos_ok and len(corridas) == repeticiones else "NO_APROBADO",
        "limitaciones": [
            "Ensayo local WSL2: no incluye latencia ni tráfico de Internet o acceso remoto real.",
            "TLS incluye comprobación del token y certificado en cada recurso; HTTP no tiene autenticación. La diferencia no es coste criptográfico puro.",
            "No equivale a medir el sobrecoste de encapsulación de un túnel VPN IP.",
            "CPU/RAM del servidor TLS solo se mide si se pasa --pid-tls; RAM es RSS, CPU porcentaje de un núcleo.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="RS3: rendimiento cifrado TLS 1.3/mTLS frente a HTTP directo")
    parser.add_argument("--usuarios", type=int, default=10)
    parser.add_argument("--mensajes", type=int, default=20)
    parser.add_argument("--bytes", type=int, default=256)
    parser.add_argument("--repeticiones", type=int, default=2)
    parser.add_argument("--puerto-http", type=int, default=9080)
    parser.add_argument("--espera-http", type=float, default=60.0,
                        help="Segundos máximos para levantar HTTP local (5-180)")
    parser.add_argument("--url", default="https://localhost:9443")
    parser.add_argument("--pid-tls", type=int, default=None)
    parser.add_argument("--json", type=Path, default=RAIZ / "bench/resultados/comparativa_cifrado.json")
    args = parser.parse_args()
    try:
        doc = asyncio.run(comparar(args.usuarios, args.mensajes, args.bytes, args.repeticiones,
                                   args.url, args.puerto_http, args.pid_tls, args.espera_http))
    except (RuntimeError, ValueError, OSError, httpx.HTTPError) as exc:
        print(f"[ERROR] Comparativa no completada: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\n[RS3] RESULTADO: {doc['resultado']} | Informe: {args.json}", flush=True)
    # El dashboard se regenera también si alguna repetición no fue aprobada.
    # No altera las medidas ni cambia el resultado de la comparativa.
    try:
        from tools.informe_rs3 import generar_informe
        destino = RAIZ / "bench" / "resultados" / "informe_rs3.html"
        info = generar_informe(RAIZ / "bench" / "resultados", destino, adicionales=[args.json])
        print(f"[RS3] Gráficas HTML: {info['archivo']} "
              f"({info['validas']}/{info['repeticiones']} repeticiones válidas)", flush=True)
    except (OSError, ValueError, TypeError) as exc:
        print(f"[RS3] Aviso: no se pudo generar el informe HTML: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
    return 0 if doc["resultado"] == "APROBADO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
