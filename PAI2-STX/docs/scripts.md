# Qué hace cada script y herramienta · BYODSEC (PAI-2)

Referencia de todos los ficheros ejecutables del proyecto: qué hacen, dónde se
ejecutan, qué necesitan y qué producen. Los **scripts bash** (`scripts/`) montan
y operan el laboratorio en **Ubuntu/WSL2**. Las **herramientas Python**
(`tools/`, `src/*/cli.py`) ejecutan pruebas y utilidades y se pueden lanzar en
Ubuntu o en Windows (con `py -m ...`).

> Convención: `laboratorio.sh` es el único punto de entrada recomendado; los
> `scripts/*.sh` son los pasos que ese orquestador invoca. Las herramientas
> nuevas de las tareas 6–10 están marcadas con **(nuevo)**.

---

## 1. Orquestador

| Fichero | Para qué sirve | Dónde / cómo |
|---|---|---|
| `laboratorio.sh` | Punto de entrada único. Sin argumentos: instala + arranca + prueba + abre el menú. Órdenes: `instalar`, `arrancar`, `probar`, `menu`, `estado`, `parar`, `entregar`. Opciones: `--sin-vpn`, `--sin-menu`. | Ubuntu/WSL2: `bash laboratorio.sh [orden]` o desde PowerShell `wsl bash laboratorio.sh` |

## 2. Pasos del laboratorio (`scripts/`)

| Fichero | Función | Lo invoca |
|---|---|---|
| `scripts/comun.sh` | Rutas, colores, carga de credenciales locales (`~/.config/byodsec`), utilidades de puertos/PID. Se carga con `source`; no se ejecuta solo. | Todos los `scripts/*.sh` |
| `scripts/1_dependencias.sh` | Comprueba Ubuntu/WSL2, systemd y `/dev/net/tun`; instala paquetes (openssl, curl, gnupg, iproute2, **tcpdump**, **iperf3**) y crea el entorno Python en `~/.local/share/byodsec/venv`. | `laboratorio.sh instalar` |
| `scripts/2_pki_y_usuarios.sh` | Crea la CA corporativa, el certificado del servidor y los 300 usuarios RF5 con su certificado (RF5, RS1). | `laboratorio.sh instalar` |
| `scripts/3_access_server.sh` | Instala y configura **OpenVPN Access Server**: repositorio oficial verificado por huella, HTTPS propio verificable, **TLS 1.3 mínimo** en VPN y web, **cifrado de datos AEAD** (`vpn.server.data_ciphers`), API REST, admin local con contraseña aleatoria y usuario VPN de demostración bloqueado (`deny=true`). (VPN, RS2) | `laboratorio.sh instalar` |
| `scripts/4_servicios.sh` | Arranca el gateway mTLS (`:9443`), el registro RF1 (`:8444`) y el timer systemd del reconciliador RF4. | `laboratorio.sh arrancar` |
| `scripts/5_pruebas.sh` | Ejecuta toda la batería (pytest, auditoría PKI, ataques TLS, RS2 real, E2E real, API REST) y escribe las evidencias y `resumen_pruebas.txt`. | `laboratorio.sh probar` |
| `scripts/estado.sh` | Diagnóstico: datos de acceso, servicios, puertos y última batería de pruebas. `--resumen` muestra solo los accesos. | `laboratorio.sh estado` |
| `scripts/parar.sh` | Detiene el gateway y el registro (Access Server y el reconciliador siguen como servicios systemd). | `laboratorio.sh parar` |
| `scripts/empaquetar_entrega.sh` | Genera `../PAI2-STX.zip` sin secretos (excluye claves, SQLite, CSV de contraseñas, `.ovpn`, entornos, `*.jsonl`, `*.pcap`) y comprueba que el ZIP no contiene material sensible. | `laboratorio.sh entregar` |

## 3. Scripts manuales (`scripts/manual/`) — necesitan el túnel real o sudo

| Fichero | Función | Uso | Requisito (punto) |
|---|---|---|---|
| `capturar_trafico.sh` | Captura 60 s en la interfaz **exterior** (pública). El tráfico debe verse cifrado (TLS 1.3 / OpenVPN). | `sudo bash scripts/manual/capturar_trafico.sh eth0` | RS4 (9) |
| `capturar_tunel.sh` **(nuevo)** | Captura 60 s **dentro** del túnel (`as0t*`/tun). El mismo tráfico aparece en claro: demuestra que viajaba cifrado por fuera. | `sudo bash scripts/manual/capturar_tunel.sh as0t0` | RS4 (9) |
| `exportar_logs_as.sh` **(nuevo)** | Exporta de Access Server (vía `logdba`) las conexiones/desconexiones VPN y los intentos de autenticación fallidos, más la versión y cipher TLS del **canal de control** OpenVPN. CSV/TXT sin secretos. | `sudo bash scripts/manual/exportar_logs_as.sh` | RS4 (9), RS2 (6) |
| `medir_iperf.sh` | Comparativa iperf3 directa/VPN contra el mismo destino. | `bash scripts/manual/medir_iperf.sh IP directa\|vpn` | RS3 (8) |

## 4. Herramientas Python (`tools/`)

| Fichero | Función | Requisito |
|---|---|---|
| `comprobar_tls.py` **(ampliado)** | RS2 en los servicios en marcha: verifica TLS 1.3 con su cipher suite y **grupo efímero (PFS, X25519)**, y que se **rechazan TLS 1.0, 1.1 y 1.2** (vía `openssl s_client` con `@SECLEVEL=0`, o Python como respaldo). | RS2 (6) |
| `carga_gateway.py` **(nuevo)** | RS3: lanza N sesiones RF2 simultáneas (challenge→login→/me→logout) sobre mTLS con los usuarios RF5. Mide conexiones OK/error, latencia (media/p50/p95/máx), throughput y CPU/RAM del gateway. | RS3 (7) |
| `medir_cliente.py` **(nuevo)** | RS3: mide desde el cliente con iperf3 + ping contra el mismo recurso, con y sin VPN; guarda JSON normalizado. Funciona en Windows y Linux. | RS3 (8) |
| `graficas_rendimiento.py` **(nuevo)** | RS3: dibuja `grafica_escalabilidad.png` (throughput/latencia vs concurrencia) y `grafica_overhead_vpn.png` (throughput y RTT, directa vs VPN) a partir de `bench/resultados/`. | RS3 (7, 8) |
| `ataques_vpn_real.py` **(nuevo)** | Extra (+10%): 6 ataques controlados contra el gateway en marcha (sin certificado, CA ajena, contraseña errónea, suplantación por contraseña ajena, token robado con otro certificado, reutilización tras logout). Todos deben ser rechazados; queda traza en auditoría. | Extra (10) |
| `exportar_auditoria_csv.py` **(nuevo)** | RS4: reúne los JSONL de auditoría (RF1, RF2/VPN, RF4) en `evidencias/logs/auditoria_accesos.csv` depurado (sin secretos), apto para entregar. | RS4 (9) |
| `ataque_opcional.py` | Extra (+10%): ataques TLS en loopback con certificados efímeros (servidor impostor con CA desconocida, cliente sin certificado, cliente TLS 1.2). | Extra (10) |
| `auditar_rf1_rf5_pki.py` | Auditoría de los 300 usuarios, roles y certificados. | RF5, RS1 |
| `comprobar_access_server.py` | Comprueba que la API REST de Access Server responde (HTTPS verificado). | VPN |
| `generar_perfil_vpn.py` | Genera el perfil `.ovpn` *userlogin* por REST. | VPN |
| `prueba_e2e_laboratorio.py` | Prueba extremo a extremo real RF1→RF2→VPN→RF4 contra los servicios en marcha. | RF1, RF2, RF4, VPN |
| `recurso_interno_vpn.py` | API REST de laboratorio que simula un recurso interno, enlazada solo a la IP de la interfaz VPN. | VPN (manual) |
| `probar_tunel.py` | Comprueba el acceso al recurso interno antes/durante/después de la VPN (fases sin-vpn/con-vpn/tras-logout). | VPN, RF4 (manual) |

## 5. CLI de aplicación (`src/*/cli.py`, módulos)

| Comando | Función | Requisito |
|---|---|---|
| `python -m pki.scripts.pki crear-ca \| emitir-servidor \| emitir-cliente \| revocar \| generar-crl \| verificar` | Ciclo de vida de la PKI corporativa X.509. | RS1 |
| `python -m src.rf5.cli precargar \| certificados \| resumen` | Precarga de usuarios RF5 y emisión de sus certificados. | RF5 |
| `python -m src.client.interfaz` | Menú de consola del cliente BYODSEC (RF1/RF2/RF4/RF5/VPN). | RF1, RF2, RF4 |
| `python -m src.gateway.ejecutar` / `ejecutar_registro` | Arranque TLS 1.3/mTLS del gateway y del registro RF1. | RF2/RF4/VPN, RF1 |
| `python -m src.vpn_rest_as.reconciliar` | Cierra por REST las VPN de sesiones caducadas o revocadas (lo lanza el timer). | RF4 |

## 6. Código fuente de auditoría (nuevo en el punto 9)

| Fichero | Función |
|---|---|
| `src/common/auditoria.py` **(nuevo)** | Registro común en JSONL de eventos de acceso (login OK/fallido, autorización VPN OK/denegada), sin contraseñas, tokens ni claves. Escribe `evidencias/logs/accesos-audit.jsonl`. |
| `src/server/app.py::_auditar` | Auditoría de RF1 (registro de dispositivos) → `rf1-audit.jsonl`. |
| `src/rf4/auditoria.py` | Auditoría de RF4 (cierres de sesión) → `rf4-audit.jsonl`. |
