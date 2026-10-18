# Matriz de trazabilidad · BYODSEC (PAI-2)

Cada requisito se enlaza con el código que lo implementa, las pruebas que lo
verifican y la evidencia que genera `bash laboratorio.sh` (en `evidencias/`).
Las pruebas `tests/…` se ejecutan aisladas (SQLite, PKI y logs temporales).

## 1. Requisitos → código → pruebas → evidencia

| Req. | Qué se exige | Código | Pruebas automáticas | Evidencia del laboratorio |
|---|---|---|---|---|
| **RF1** | Registro del dispositivo y emparejamiento usuario–clave pública; sin reutilizar dispositivo ni clave | `src/server/app.py` (API `:8444`), `src/gateway/ejecutar_registro.py` (TLS 1.3), `src/common/base_datos.py` (tabla `device_pairings` + disparadores de inmutabilidad), `src/server/usuarios.py` (alta manual) | `test_rf1_registration.py` (4), `test_vpn_refuerzo_rf1_rf2_rf4.py::test_rf1_inmutabilidad_sqlite_y_revocacion_permitida`, `test_interfaz_consola.py::test_rf1_alta_*` (2) | `e2e_laboratorio.json` pasos RF1 (alta 201, duplicado 409, credenciales 401); `rf1-audit.jsonl` |
| **RF2** | Inicio de sesión: certificado mTLS + usuario/contraseña, una sola vez por desafío | `src/rf2/autenticacion.py` (firma del desafío, CA, revocados, emparejamiento, scrypt), `src/rf2/sesiones.py` (desafíos de un uso, tokens solo como hash), `src/rf2/rutas.py`, `src/gateway/protocolo_mtls.py` (certificado del socket TLS, no de cabeceras), `src/gateway/app.py` | `test_rf2_rf4.py` (11: contraseña, firma, certificado ajeno, desafío reutilizado, HTTP, bloqueo, revocación, caducidad), `test_rf2_rf4_mtls_integracion.py` (sockets reales TLS 1.3/mTLS + token robado con otro certificado), `test_rf2_rf5.py`, `test_interfaz_consola.py` | `e2e_laboratorio.json` pasos RF2 (login 200, /me 200, contraseña incorrecta 401) |
| **VPN** | Túnel VPN SSL/TLS (OpenVPN Access Server) habilitado solo tras RF2, un dispositivo por cuenta, perfiles `userlogin` | `src/vpn_rest_as/client.py` (API REST oficial, HTTPS verificado), `rutas.py` (`/api/v1/vpn/authorize`, `/api/v1/vpn/me`), `autorizaciones.py` (concesiones ligadas al token RF2), `provision.py` (cuentas `deny=true`), `tools/generar_perfil_vpn.py`, `scripts/3_access_server.sh` | `test_vpn_rest_as.py` (12), `test_vpn_rest_integracion.py` (8), `test_vpn_rest_userprop.py` (11), `test_vpn_refuerzo_rf1_rf2_rf4.py` (segundo dispositivo, compensación si falla authorize, perfil userlogin) | `e2e_laboratorio.json` pasos VPN (estado propio, segundo dispositivo 409); perfil `~/.config/byodsec/clients/rf5_inv_001.ovpn` |
| **RF4** | Cierre de sesión: invalidar acceso y desmontar el túnel | `src/vpn_rest_as/rf4.py` (deny → disconnect → verificación por GET → revocación de todas las sesiones), `src/vpn_rest_as/reconciliar.py` + timer systemd (sesiones caducadas/revocadas), `src/rf4/*` (modo sin VPN y auditoría) | `test_rf2_rf4.py::test_login_me_logout_*`, `test_vpn_rest_as.py::test_logout_*`, `test_vpn_rest_integracion.py::test_logout_*`, `test_vpn_refuerzo_rf1_rf2_rf4.py::test_rf4_*` (3), `test_vpn_reconciliar.py` | `e2e_laboratorio.json` pasos RF4 (logout 200 + token anterior 401 + VPN bloqueada y desconexión verificada); `rf4-audit.jsonl` |
| **RF5** | 300 usuarios precargados: 100 PDI, 100 PAS, 100 Investigadores, con certificado | `src/rf5/gestion.py`, `src/rf5/cli.py`, `scripts/2_pki_y_usuarios.sh` | `test_rf5.py` (6), `test_rf5_recursos.py` (4), `test_rf2_rf5.py` | `auditoria_rf1_rf5_pki.json` (300 usuarios, 3 roles, certificados verificados) |
| **RS1** | PKI corporativa y autenticación mutua con certificados X.509 | `pki/scripts/pki.py` (CA, servidor, cliente, revocación, CRL), `src/server/tls.py` (`CERT_REQUIRED`), `tools/auditar_rf1_rf5_pki.py` | `test_pki.py` (3, incl. OpenSSL `-x509_strict`), `test_mtls.py` (3), `test_rf2_rf4.py::test_certificado_revocado_por_ca_rechazado`, `test_rf5_recursos.py::test_auditoria_*` | `auditoria_rf1_rf5_pki.json`; `e2e_laboratorio.json` paso RS1 (cliente sin certificado rechazado) |
| **RS2** | TLS 1.3, cifrado AEAD y PFS; rechazo de versiones antiguas | `src/server/tls.py`, `src/gateway/ejecutar*.py` (solo TLS 1.3, sin tickets), `scripts/3_access_server.sh` (TLS 1.3 mínimo en VPN y web de Access Server), `tools/comprobar_tls.py` | `test_tls.py` (2), `test_mtls.py::test_mtls_rechaza_cliente_tls_12` | `tls_servicios.json`: versión y *cipher suite* negociadas en :9443, :8444 y :943 y rechazo de TLS 1.2 |
| **RS3** | Rendimiento con hasta 300 usuarios; comparación con/sin VPN | `scripts/manual/medir_iperf.sh` | — (medición manual) | `bench/resultados/*.json` (manual). Limitación: Access Server gratuito admite 2 túneles simultáneos |
| **RS4** | Trazabilidad: capturas y registros sin secretos | `scripts/manual/capturar_trafico.sh`, `src/rf4/auditoria.py`, `src/server/app.py::_auditar` | `test_rf2_rf4.py::test_login_me_logout_rechaza_reutilizacion_y_audita` | `evidencias/pcap/*.pcap` (manual), `evidencias/logs/*.jsonl`, `resumen_pruebas.txt` |
| **Extra (+10 %)** | Ataques controlados contra TLS | `tools/ataque_opcional.py` (CA falsa, cliente sin certificado, TLS 1.2) | `test_ataque_opcional.py` | `evidencias/ataques/tls_opcional.json` |

## 2. Inventario: cada fichero, para qué sirve y quién lo usa

### Laboratorio (bash)

| Fichero | Función | Lo invoca |
|---|---|---|
| `laboratorio.sh` | **Único punto de entrada**: `todo`, `instalar`, `arrancar`, `probar`, `menu`, `estado`, `parar`, `entregar` | El usuario / profesor |
| `scripts/comun.sh` | Rutas, mensajes, carga de credenciales locales, utilidades de puertos/PID | Todos los `scripts/*.sh` |
| `scripts/1_dependencias.sh` | Ubuntu/WSL2, systemd, `/dev/net/tun`, paquetes, entorno Python | `laboratorio.sh instalar` |
| `scripts/2_pki_y_usuarios.sh` | CA, certificado del servidor, 300 usuarios RF5 y sus certificados (RF5, RS1) | `laboratorio.sh instalar` |
| `scripts/3_access_server.sh` | Instala y configura OpenVPN Access Server, HTTPS verificado, TLS 1.3, API REST, usuario demo bloqueado y perfil `.ovpn` (VPN, RS2) | `laboratorio.sh instalar` |
| `scripts/4_servicios.sh` | Arranca gateway :9443, registro :8444 y el timer reconciliador RF4 | `laboratorio.sh arrancar` |
| `scripts/5_pruebas.sh` | Ejecuta todas las pruebas y escribe las evidencias y el resumen | `laboratorio.sh probar` |
| `scripts/estado.sh`, `scripts/parar.sh` | Diagnóstico y parada de servicios | `laboratorio.sh estado / parar` |
| `scripts/empaquetar_entrega.sh` | ZIP de entrega sin claves, SQLite, CSV, `.ovpn` ni entornos | `laboratorio.sh entregar` |
| `scripts/manual/capturar_trafico.sh` | Captura `.pcap` en la interfaz externa (RS4) | Manual (`sudo`) |
| `scripts/manual/medir_iperf.sh` | Comparativa iperf3 directa/VPN (RS3) | Manual |

### Aplicación (Python)

| Módulo | Función | Requisito |
|---|---|---|
| `src/common/base_datos.py`, `seguridad.py`, `config_tls.py` | Esquema SQLite común, hash scrypt, rutas PKI | RF1, RF2, RF5 |
| `src/server/app.py`, `usuarios.py` | API de registro de dispositivos y alta manual de usuarios | RF1 |
| `src/server/tls.py` | Contexto TLS 1.3 con certificado cliente obligatorio; huella de clave | RS1, RS2 |
| `src/gateway/app.py`, `ejecutar.py` | **Gateway único** (RF2 + RF4; con `BYODSEC_VPN_REST=1` añade VPN REST) | RF2, RF4, VPN |
| `src/gateway/ejecutar_registro.py` | Servidor HTTPS TLS 1.3 del registro RF1 | RF1, RS2 |
| `src/gateway/protocolo_mtls.py` | Pasa a la app el certificado validado en el socket TLS | RS1, RF2 |
| `src/rf2/*` | Desafíos, login de dos factores y sesiones | RF2 |
| `src/rf4/*` | Logout de aplicación y auditoría de cierres | RF4, RS4 |
| `src/rf5/*` | Precarga de usuarios y certificados | RF5 |
| `src/vpn_rest_as/*` | Integración REST con Access Server (autorizar, estado, logout, reconciliador, alta) | VPN, RF4 |
| `src/client/servicio_consola.py`, `interfaz.py` | Cliente mTLS y menú de consola | RF1, RF2, RF4, RF5 |
| `pki/scripts/pki.py` | Gestión de la PKI corporativa | RS1 |
| `tools/auditar_rf1_rf5_pki.py` | Auditoría de usuarios, roles y certificados | RF5, RS1 |
| `tools/comprobar_tls.py` | Versión y cipher suite negociadas en los servicios reales | RS2 |
| `tools/prueba_e2e_laboratorio.py` | Prueba extremo a extremo RF1 → RF2 → VPN → RF4 | RF1, RF2, RF4, VPN |
| `tools/comprobar_access_server.py` | Comprueba la API REST de Access Server | VPN |
| `tools/generar_perfil_vpn.py` | Perfil `.ovpn` userlogin por REST | VPN |
| `tools/ataque_opcional.py` | Ataques TLS controlados | Extra |
| `tools/recurso_interno_vpn.py`, `tools/probar_tunel.py` | Recurso interno solo accesible por el túnel y comprobación antes/durante/después | VPN, RF4 (manual) |

## 3. Pruebas que requieren el túnel real (manuales)

Se apoyan en herramientas del repositorio pero necesitan OpenVPN Connect en el
cliente, por lo que no se pueden automatizar en `laboratorio.sh`:

1. Importar `rf5_inv_001.ovpn` en OpenVPN Connect, iniciar sesión RF2 en el menú
   (opción 2) y conectar el túnel; la opción 9 debe mostrar `Conectado: True`.
2. Recurso interno: `python -m tools.recurso_interno_vpn --host <IP as0t*>` en
   Ubuntu y `py -m tools.probar_tunel --fase sin-vpn|con-vpn|tras-logout --ip <IP>`
   en el cliente (resultados en `evidencias/logs/acceso_vpn.jsonl`).
3. RF4 real: opción 4 del menú (logout) y comprobar que el túnel cae y no puede
   reconectarse sin un nuevo login RF2.
4. RS4: `sudo bash scripts/manual/capturar_trafico.sh eth0` durante la conexión.
5. RS3: `bash scripts/manual/medir_iperf.sh <IP> directa` y `… vpn`.
