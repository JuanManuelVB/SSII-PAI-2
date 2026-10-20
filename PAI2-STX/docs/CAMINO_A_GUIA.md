# BYODSEC — Camino A: TLS 1.3/mTLS sin OpenVPN

## Objetivo
Demostrar **comunicación de aplicación** Windows → Ubuntu WSL2 sobre TLS 1.3, con verificación mutua X.509, credenciales RF2, transferencia de un mensaje de prueba, recurso protegido y revocación RF4. El modo A **NO** implementa ni desmonta un túnel IP/OpenVPN. Se utiliza porque el profesor ha confirmado que acepta esta alternativa.

## 0. Precauciones
- Desconecta OpenVPN Connect durante la demostración A. No necesitas Access Server ni contraseña administrativa.
- No ejecutes `Iniciar_BYODSEC.cmd` en este modo: el lanzador antiguo activa integración VPN.
- Conserva intactas la CA corporativa, SQLite, certificados y contraseñas del entorno de trabajo.
- No publiques las claves `.key`, `credenciales.csv`, la SQLite ni perfiles `.ovpn`.
- El paquete incluye solo 6 archivos Python modificados/nuevos y este documento; no incluye secretos.
- Si has cambiado los archivos de código desde el ZIP `PAI2-STX(2).zip`, **compara los cambios** antes de sobrescribirlos.

## 1. Aplicar el parche
Haz copia de seguridad o commit en tu repositorio. Descomprime `BYODSEC_CAMINO_A_PARCHE.zip` **en la raíz de `PAI2-STX`**, conservando rutas `src/`, `tests/` y `docs/`.

Añadidos: `src/recursos/__init__.py`, `src/recursos/rutas.py` y esta guía.
Modificados: `src/gateway/app.py`, `src/client/servicio_consola.py`, `src/client/interfaz.py`, `tests/test_rf2_rf4_mtls_integracion.py`.

Cambios: API REST protegida `GET /api/v1/resources/demo` y `POST /api/v1/resources/echo` con token+certificado mTLS; opción 9 de la consola demuestra intercambio de datos si VPN_REST no está activo; opción 7 lo incluye en el ciclo; test real comprueba permisos antes/después del logout.

## 2. Arrancar los servicios (desde la raíz `PAI2-STX`)
**Terminal WSL 1**:
```bash
source .venv-wsl/bin/activate
unset BYODSEC_VPN_REST BYODSEC_VPN_DEFAULT_DENY
python -m src.gateway.ejecutar --port 9443
```
**Terminal WSL 2**:
```bash
source .venv-wsl/bin/activate
python -m src.gateway.ejecutar_registro --port 8444
```
Mantenlas abiertas. No iniciar por HTTP sin TLS (`uvicorn src.gateway.app:app` sería incorrecto).

**PowerShell Windows**, desde la carpeta de proyecto:
```powershell
Remove-Item Env:BYODSEC_VPN_REST -ErrorAction SilentlyContinue
py -m src.client.interfaz --url https://localhost:9443
```

## 3. Demostraciones manuales para capturar
1. **RF5**: en consola opción 5 (300 usuarios, perfiles); ejecutar auditoría de PKI desde WSL:
```bash
python -m tools.auditar_rf1_rf5_pki --total 300
```
2. **RF2**: opción 2 `rf5_inv_001`, contraseña corporativa de tu CSV local, respuesta 200; opción 3 sesión 200.
3. **Recurso real**: opción 9 (sin VPN_REST): `GET /api/v1/resources/demo` protegido y `POST /api/v1/resources/echo` que devuelve SHA-256 verificado por cliente. La ruta usa TLS/mTLS y una sesión RF2.
4. **RF4**: opción 4; token revocado, cliente TLS cerrado y petición con token previo obtiene HTTP 401.
5. **Demostración completa**: opción 7 para reproducir RF2 → GET/POST recurso → logout → 401. Evita volver a usar opción 7 durante una sesión activa.
6. **RF1**: mantener gateway de registro :8444, opción 1 para un dispositivo nuevo de un usuario existente; después opción 8 muestra el nuevo certificado. No sobrescribas un dispositivo existente.
7. **Pruebas negativas**: intentar acceso sin certificado con `curl.exe -v --max-time 7 https://localhost:9443/api/v1/resources/demo` (no debe devolver documento), y negociación TLS 1.2 con `openssl s_client -connect 127.0.0.1:9443 -servername localhost -tls1_2` en WSL (debe fallar).

## 4. Batería automática y cripto real
**Terminal WSL 3** (mantén servidores iniciados para el verificador de servicios):
```bash
mkdir -p evidencias/logs evidencias/pcap bench/resultados
python -m pytest -v tests/test_mtls.py tests/test_tls.py tests/test_rf2_rf4.py tests/test_rf2_rf4_mtls_integracion.py tests/test_rf1_registration.py tests/test_rf5.py tests/test_interfaz_consola.py > evidencias/logs/caminoA_pytest.txt 2>&1
python -m tools.comprobar_tls --sin-access-server --json evidencias/logs/caminoA_tls.json
python -m tools.auditar_rf1_rf5_pki --total 300 > evidencias/logs/caminoA_pki.txt
```
Comprobar `tail -n 15 evidencias/logs/caminoA_pytest.txt`. No afirmar 300 conexiones simultáneas porque haya 300 certificados.

## 5. Capturar el canal protegido
**Ubuntu WSL** (con gateway activo):
```bash
sudo tcpdump -i any -nn -s 0 -w evidencias/pcap/caminoA_mtls.pcap 'tcp port 9443'
```
Mientras captura, desde la consola Windows realiza la opción 7 o `2, 9, 4`. Pulsa Ctrl+C en la captura. Valida tráfico:
```bash
sudo tcpdump -nn -r evidencias/pcap/caminoA_mtls.pcap | head
```
Guardar pcap solo si contiene paquetes. No debe verse la contraseña ni el mensaje HTTP sin descifrar en la captura TLS. **No usar la ausencia de texto como única prueba criptográfica**: adjuntar además `caminoA_tls.json` (versión/cipher) y tests.

## 6. Escalabilidad: concurrencia del gateway
*La siguiente carga prueba sesiones TLS/mTLS de aplicación, NO 300 túneles VPN.*
```bash
python -m tools.carga_gateway --usuarios 10 --json bench/resultados/caminoA_10.json
python -m tools.carga_gateway --usuarios 50 --json bench/resultados/caminoA_50.json
python -m tools.carga_gateway --usuarios 100 --json bench/resultados/caminoA_100.json
python -m tools.carga_gateway --usuarios 300 --json bench/resultados/caminoA_300.json
```
Vigila CPU/RAM y registra errores/limitaciones reales; si la ejecución de 300 genera errores, no presentarla como satisfactoria. La herramienta actual mide ciclos de autenticación; queda por realizar una comparación controlada de rendimiento TLS contra tráfico sin cifrar si el informe pretende cubrir ese apartado del PDF.

## 7. Evidencias mínimas a guardar
- `01_RF5_300_certificados.png`: auditoría con total 300 y sin problemas.
- `02_RF2_login.png`: HTTP 200 sin mostrar contraseña/token.
- `03_recurso_TLS.png`: opción 9, recurso/sha256 de mensaje.
- `04_RF4_logout.png`: HTTP 200 y 401 de reutilización.
- `05_tests_y_tls.png`: pruebas aprobadas y `caminoA_tls.json` con cipher AEAD y versión 1.3.
- `06_rechazo_sin_cert.png`: sin certificado no hay recurso.
- `07_Wireshark.png` y `caminoA_mtls.pcap`: datos cifrados TLS en tránsito.
- `08_carga.png`: resultado de carga real y sus limitaciones.

### Alcance real
Camino A es un **canal seguro de aplicación** aceptado por el profesor. No afirma que un recurso sea alcanzable por túnel IP ni que RF4 desconecte OpenVPN; RF4 revoca el token y termina los sockets HTTPS de ese cliente. El servidor no tiene forma de "destruir" material efímero del cliente de otra manera que cerrar conexiones TLS y descartar las sesiones de aplicación. 
