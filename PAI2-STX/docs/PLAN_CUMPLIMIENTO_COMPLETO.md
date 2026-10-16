# BYODSEC — Manual reproducible, matriz de requisitos y pruebas

## AVISO — Alcance verificado

El código Python y los tests locales no reemplazan **una demostración real en el servidor WSL**. Esta entrega contiene un gateway FastAPI TLS1.3/mTLS, RF1/RF2/RF4/RF5, la capa REST administrativa de **OpenVPN Access Server 3.2+** y la demo opcional de TLS. NO contiene máquinas virtuales, claves, contraseñas ni certificados privados. No es una validación realizada contra el OpenVPN Access Server del usuario. **La licencia gratuita de Access Server impide demostrar 300 túneles simultáneos**; no presentar pruebas con 300 usuarios SQLite como 300 VPN.

## Diferenciar tres capas criptográficas

1. `pki/ca/ca.crt`: CA del proyecto BYODSEC que verifica dispositivos mTLS y API protegida RF2. Las claves privadas de usuarios viven en sus dispositivos.
2. HTTPS administrativo de **Access Server** en `https://localhost:943`: certificado web propio, validado mediante `BYODSEC_AS_CA_BUNDLE`. Debe coincidir el SAN del certificado con el hostname usado. No es necesariamente el mismo certificado que la CA BYODSEC.
3. OpenVPN Access Server gestiona certificados/perfiles VPN **independientes por defecto**. Para acreditar el RS1 completamente sobre el TÚNEL real se debe documentar la relación de identidades y confianza de ambas PKI y la validación mTLS OpenVPN. No asumir que compartir nombre de usuario es suficiente.

La API administrativa REST nunca se expone al usuario: **cliente BYODSEC → HTTPS/mTLS FastAPI → HTTPS REST Access Server**. La VPN transporta paquetes de red mediante OpenVPN, no mediante HTTP.

## Entorno y configuración

- Python >=3.11 para BYODSEC, `pip install -r requirements.txt` y `pip install -r requirements-interfaz.txt` si quieres menú.
- Access Server >=3.2 en Ubuntu WSL2. No arrancar Access Server y OpenVPN Community simultáneamente en los mismos puertos.
- Aplicar TLS 1.3 en ambos servicios con `sudo bash vpn/scripts/configurar_as_tls13.sh --apply`. Comprobar en el panel Admin → TLS Settings y con clientes reales; restricción de cipher suites AES-GCM/ChaCha20-Poly1305 requiere verificación manual de negociación.
- Crear **certificados reales** BYODSEC en el equipo local con las herramientas PKI originales, no reutilizar los del desarrollador. Conservar privada la CA raíz, preferentemente desconectada; en el laboratorio, proteger ACLs y almacenar claves fuera de Git. No entregar claves.
- Crear usuarios en SQLite mediante `python -m src.rf5.cli precargar --total 300` (si aún no existen) y emitir certificados según CLI. No repetir una generación de CA ya existente sin migrar certificados.
- Ejecutar `python -m src.vpn_rest_as.provision --limit 3` para ver previa y `--apply` para dar de alta **solo en el Access Server del laboratorio** tres cuentas bloqueadas mediante REST. Estas cuentas no tienen contraseñas propias en Access Server todavía: configurar autenticación local o proveedor externo para cada cuenta en el panel; **nunca trasladar contraseñas del CSV por Git**.
- Confirmar que las cuentas Access Server están en `deny=true` y `autologin=false` antes de habilitar la integración REST. No habilitar perfiles autologin que salten credenciales o puedan reconectarse sin RF2.
- Configurar variables de entorno en la misma terminal donde arrancarás BYODSEC; NO guardar secretos en Git:

```bash
export BYODSEC_AS_URL=https://localhost:943
export BYODSEC_AS_ADMIN_USER=openvpn
read -r -s -p 'Contraseña de admin: ' BYODSEC_AS_ADMIN_PASSWORD; echo
export BYODSEC_AS_ADMIN_PASSWORD
# Reemplazar por CA que verifica el certificado web ACTIVO de AS:
export BYODSEC_AS_CA_BUNDLE=/usr/local/openvpn_as/etc/web-ssl/ca.crt
# Solo después de constatar política inicial de deny=true en las cuentas:
export BYODSEC_VPN_DEFAULT_DENY=confirmed
export BYODSEC_VPN_REST=1
```

**Comprobar la CA antes**:

```bash
openssl s_client -connect localhost:943 -servername localhost -verify_return_error </dev/null
python -m tools.comprobar_access_server
```

No usar `verify=False`. Si el certificado web no incluye SAN `localhost`, emitir o instalar un certificado válido para el DNS realmente utilizado y ajustar `BYODSEC_AS_URL`.

- Arrancar en la raíz del proyecto `python -m src.vpn_rest_as.ejecutar` (gateway **alternativo**, evita duplicar `/logout` de `src.gateway.ejecutar`). Ejecutar registro RF1 en servicio independiente con `python -m src.gateway.ejecutar_registro`.
- Cliente: `python -m src.client.interfaz`. Debe contar con certificado y clave individual vinculados a `device_pairings` SQLite y con cuenta propia de Access Server. El modo REST hace `POST /api/v1/vpn/authorize` tras autenticar RF2. Entonces conectar perfil **OpenVPN del mismo usuario**, desde OpenVPN Connect, no un perfil compartido. La conexión OpenVPN es una operación del cliente VPN externo, no de la API REST.
- La plantilla `vpn/scripts/byodsec-vpn-reconciliar.timer.example` ejecuta `src.vpn_rest_as.reconciliar` periódicamente para bloquear y desconectar sesiones expiradas o revocadas. Personalizar usuario y rutas, cargar las variables vía fichero protegido `/etc/byodsec/rest.env` (chmod 600); habilitar el timer solamente una vez probado en WSL.
- Después del logout, BYODSEC primero deniega nuevas conexiones con `POST /api/userprop/set` (`deny=true`), después solicita el corte con `POST /api/vpn/client/disconnect`, y finalmente revoca tokens del usuario en SQLite. La respuesta 200 acredita la petición y que las APIs respondieron; confirmar desconexión efectivamente observada en `/api/v1/vpn/me` / panel Access Server.
- Un nuevo login válido RF2 puede autorizar nueva conexión. No debe poder hacerlo usando un token viejo.

## Endpoints públicos del gateway BYODSEC (requieren TLS1.3 + mTLS)

| Endpoint | RF | Efecto |
|---|---|---|
| `POST /api/v1/devices/register` (:8444) | RF1 | Emite X.509 y vincula identidad/dispositivo, canal TLS de servidor en inscripción |
| `POST /api/v1/sessions/challenge` | RF2 | Desafío efímero anti-replay |
| `POST /api/v1/sessions/login` | RF2 | mTLS + usuario/contraseña + firma, token hash en SQLite |
| `GET /api/v1/sessions/me` | RF2 | Consulta autenticada |
| `POST /api/v1/vpn/authorize` | VPN | Permite el usuario de la sesión RF2 por REST, denegado por defecto |
| `GET /api/v1/vpn/me` | VPN | Estado de conexiones **solo del usuario autenticado** |
| `POST /api/v1/sessions/logout` | RF4 | Deniega reconexión, desconecta y revoca sesiones |

Los endpoints administrativos reales de Access Server no se publican en el gateway a los clientes.

## Conexión de compañeros (3 ordenadores)

Cada compañero clona la rama main (sin secrets), instala un **cliente OpenVPN** y solicita al administrador del laboratorio que le cree una cuenta AS propia con perfil NO autologin y certificado propio. El usuario debe estar también en la SQLite del servidor BYODSEC y su dispositivo registrado en RF1/RF5. Solo el servidor guarda SQLite y credenciales de administración AS; los clientes no tienen acceso administrativo.

- **En la misma Wi-Fi:** usar la IP LAN de Windows que hospeda WSL y habilitar acceso selectivo desde la LAN (Windows Firewall + red WSL2 modo mirrored cuando proceda). No usar `localhost` en los portátiles de los compañeros, ni confiar en que la IP `172.x.x.x` de WSL NAT sea alcanzable externamente. Comprobar en cada cliente TCP 943 (portal) y el UDP/TCP VPN que configure Access Server; puede que WSL2 NAT necesite un despliegue en VM o servidor LAN real.
- **Redes distintas:** usar un host con DNS público válido o un servicio de red privada que alcance el servidor, ajustando firewall y rutas; no abrir la consola administrativa pública ni reenviar las claves de admin.
- Requerís **3 conexiones simultáneas** pero Access Server gratuito permite 2: para los tres clientes al mismo tiempo es necesaria licencia suficiente o volver a Community con una capa REST propia (en cuyo caso la interfaz REST sería nuestra, no nativa de Community).
- Compartir con cada compañero **su propio perfil** y contraseña por un canal seguro. No se copia `ca.key`, `server.key`, ninguna clave privada ajena ni admin token. Configurar todos los certificados y usuarios de forma coherente con RF2 y VPN.

## Pruebas de aceptación (reproducibles)

```bash
python -m pytest -q tests/test_rf2_rf4.py tests/test_vpn_rest_as.py tests/test_vpn_rest_integration.py tests/test_ataque_opcional.py
python -m tools.ataque_opcional
python -m tools.comprobar_access_server
```

Completar en el entorno real:

1. RF1: registrar dispositivo nuevo, rechazar mismo `device_id` o misma clave sin revocación/reemisión.
2. RF2: login mTLS correcto; sin certificado válido / contraseña errónea / otro dispositivo / desafío reutilizado → rechazo.
3. VPN: AS en deny=true no conecta; sesión válida RF2 habilita; OpenVPN Connect establece túnel y accede solo a red interna autorizada. Confirmar 3 roles; documentar mapeo de certificados.
4. RF4: logout → denegar + disconnect; revisar `/api/v1/vpn/me` hasta sin conexiones, cerrar cliente y observar interfaz virtual desconectada; nuevo intento de conexión sin nuevo RF2 → rechazo; token antiguo `/me` → HTTP 401.
5. RS2: capturar handshake TLS1.3 y cipher suite negociada para HTTPS API **y** OpenVPN; demostrar TLS1.2 rechazado.
6. RS3: comparar el MISMO tráfico vía directa y túnel con `iperf3`, medir latencia/RTT/CPU/RAM; escalado con 10, 50, 100, 200, 300 clientes reales cuando exista capacidad licenciada. `vpn/scripts/capturar_trafico.sh` y `bench/scripts/medir_iperf.sh` son plantillas ejecutables; NO alegar que 300 SQLite cuentan como 300 conexiones VPN.
7. RS4: capturar `.pcap` en interfaz externa (sin claves) y logs de conexiones y fallos. Guardar PCAP privados si contienen IP/identidades. Auditar hora y nombre de usuario.

## Opcional (+10 %): amenazas controladas

`python -m tools.ataque_opcional` crea **tres ataques locales aislados**: servidor impostor firmado por CA desconocida, cliente sin certificado mTLS y cliente obsoleto TLS1.2. Un servidor legítimo y otro falso se crean en `127.0.0.1` con certificados efímeros; el resultado JSON se guarda en `evidencias/ataques/tls_opcional.json`. Complementar con Wireshark en interfaz externa del **VPN real** y verificar que el contenido sensible va cifrado, además de mostrar revocación de tokens. No se ha hecho MITM a terceros ni se afirma haber interceptado tráfico real de universidad.

## Matriz trazable y limitaciones

| Requisito PDF | Archivo(s) | Prueba | Estado antes de validar en WSL |
|---|---|---|---|
| RF1 | `src/server/app.py`, `src/common/base_datos.py` | `test_rf1_registration.py` | Código + pruebas locales |
| RF2 | `src/rf2/*`, `src/gateway/protocolo_mtls.py` | `test_rf2_rf4.py`, `test_rf2_rf4_mtls_integracion.py` | Código + pruebas locales |
| RF4 | `src/vpn_rest_as/rf4.py`, `src/vpn_rest_as/client.py` | `test_vpn_rest_integration.py` | REST simulado; falta comprobar cierre del túnel real |
| RF5 | `src/rf5/*`, `src/vpn_rest_as/provision.py` | `test_rf5.py` | Precarga demostrable; perfiles AS por configurar |
| RS1 | `pki/scripts/pki.py`, mTLS gateway | `test_pki.py`, `test_mtls.py` | Falta acreditar correspondencia CA OpenVPN real |
| RS2 | `src/server/tls.py`, `vpn/scripts/configurar_as_tls13.sh` | `test_tls.py`, verificación TLS en WSL | Falta captura de suites negociadas y PFS en VPN real |
| RS3 | `bench/scripts/medir_iperf.sh` | Comparativa real pendiente | 300 túneles no viables con licencia gratuita Access Server |
| RS4 | `vpn/scripts/capturar_trafico.sh`, `src/rf4/auditoria.py` | Wireshark/logs reales pendientes | No se adjuntan capturas inventadas |
| Extra (+10%) | `tools/ataque_opcional.py` | `test_ataque_opcional.py` | Demostración criptográfica local, complementar con PCAP |

## Entrega

`PAI2-STX.zip` debe contener código, tests, configuración sin secretos, logs/capturas depurados y PDF máximo 15 páginas: resumen, manual de despliegue y grado de completitud. No subir claves privadas, contraseñas, tokens, ficheros SQLite con datos reales ni la exportación completa de WSL. Fecha del PDF: **27 de octubre a las 23:59**.
