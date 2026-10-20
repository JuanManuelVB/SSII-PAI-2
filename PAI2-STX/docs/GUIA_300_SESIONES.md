# BYODSEC · RS3 — 300 sesiones de aplicación simultáneas por TLS 1.3/mTLS

## Alcance exacto

El escenario **no usa OpenVPN**: es el camino A (gateway REST HTTPS/TLS 1.3 con certificado cliente obligatorio), aceptado por el profesor. Las pruebas generan hasta 300 **sesiones de aplicación simultáneas** con usuarios y certificados **distintos**. No equivalen a 300 equipos físicos ni a 300 túneles IP de una VPN.

Cada cliente independiente realiza challenge, login, GET /sessions/me, espera en una barrera común manteniendo la sesión activa con peticiones de comprobación, y transmite **mensajes de aplicación a /api/v1/resources/echo** durante 30 segundos. Verifica la huella SHA-256 y el usuario de cada respuesta, ejecuta logout y comprueba que el token anterior recibe 401.

La prueba no mostrará APROBADO si alguno falla, si no se reúnen las 300 sesiones al inicio del periodo común o si no se completan correctamente sus mensajes y logout.

## Instalación (parche)

Desde Windows, haz copia de `src/client/interfaz.py` y extrae el ZIP en la carpeta raíz de `PAI2-STX`. Incluye:

- `tools/carga_300_sesiones.py` (herramienta nueva)
- `src/client/interfaz.py` (sustituye opción 10 del Centro de Pruebas)
- `tests/test_carga_300_sesiones_integracion.py` (test reproducible con dos identidades efímeras, opcional)
- `docs/GUIA_300_SESIONES.md` (esta guía)

Preserva el resto de archivos, la base de datos, PKI, certificados y los lanzadores del proyecto. Requiere el parche del camino A ya instalado, incluido `/api/v1/resources/echo`.

## Preparación de tu instalación

1. Abre `INICIAR_SERVIDOR_BYODSEC.cmd`. Debe estar activo el gateway `localhost:9443` en **modo A**, sin `BYODSEC_VPN_REST=1`. No levantes dos instancias en 9443.
2. Comprueba que ya existen 300 pares `.crt/.key` de RF5 y el fichero privado `pki/clients/rf5/credenciales.csv` (sin mostrarlo ni adjuntarlo).
3. En Windows abre `INICIAR_CLIENTE_BYODSEC.cmd`; menú principal: **10 Pruebas y Wireshark → 10 Mantener hasta 300 sesiones mTLS simultáneas**.
4. Primero prueba **10 usuarios durante 5 segundos**. Si funciona, 50, 100, 200 y finalmente **300 durante 30 segundos**. El cliente mostrará avance en consola.
5. El informe queda en `bench/resultados/sesiones_300.json`.

También se puede ejecutar directamente en **Ubuntu WSL**, desde la raíz del proyecto:

```bash
source .venv-wsl/bin/activate
unset BYODSEC_VPN_REST BYODSEC_VPN_DEFAULT_DENY
python -m tools.carga_300_sesiones --usuarios 10 --duracion 5 --json bench/resultados/sesiones_10.json
python -m tools.carga_300_sesiones --usuarios 300 --duracion 30 --preparacion 360 --json bench/resultados/sesiones_300.json
```

**IMPORTANTE**: La ejecución puede tardar varios minutos. La preparación usa hasta 360 s porque verificar 300 contraseñas con scrypt genera carga de CPU. El periodo común de 30 segundos **empieza después** de la preparación. Los sockets y las sesiones se mantienen con actividad periódica. No cierres el gateway ni lances simultáneamente otro benchmark.

## Resultado correcto

En consola y JSON:

- `resultado`: `APROBADO`
- `objetivo_usuarios`: 300
- `identidades_distintas`: 300
- `sesiones_validas_en_barrera`: 300
- `usuarios_completaron_periodo_con_mensajes`: 300
- `mensajes_protegidos_confirmados`: 300 o más
- `errores_de_mensajes`: 0
- `cierres_sesion_correctos`: 300
- `tokens_rechazados_tras_logout`: 300

`pico_conexiones_tcp_establecidas_gateway` es una **medida por muestreo** de sockets WSL establecidos hacia el puerto del gateway; puede ser inferior al pico real entre muestreos. `sesiones_validas_en_barrera` corresponde a la concurrencia de sesiones autenticadas, no garantiza por sí solo que exista una misma conexión TCP continua para cada token (se refuerza comprobando la actividad TLS, sockets y mensajes en el periodo común).

Si aparece `NO_APROBADO`, conserva el JSON (el fallo también es un resultado válido de la evaluación) y revisa `errores_por_motivo`. Algunas causas posibles: certificados revocados, CSV de contraseñas desactualizado, timeouts por CPU/WSL/SQLite, gateway no disponible, permisos o limitaciones de memoria.

## Evidencias recomendadas

- Captura de consola durante la barrera: `300/300 sesiones autenticadas`.
- Captura del mensaje de `APROBADO` o del fallo explicado.
- Archivo `bench/resultados/sesiones_300.json` sin secretos.
- Si deseas `.pcap`, arranca antes otra consola **WSL** con:

```bash
sudo tcpdump -i any -nn -s 0 -U -w evidencias/pcap/rs3_300_mtls.pcap 'tcp port 9443'
```

Después inicia el benchmark, detén tcpdump con Ctrl+C y comprueba que contiene paquetes. Para esta carga pueden capturarse muchos paquetes y el archivo crecer; es mejor capturar una ventana corta **durante el periodo común**, no necesariamente todos los logins.

No subas `credenciales.csv`, claves `.key`, tokens, ni la BD privada con usuarios a los entregables.
