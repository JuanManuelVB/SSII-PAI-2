# Guía de demostración, camino A

## 1. Recorrido del usuario

Desde `INICIAR_CLIENTE_BYODSEC.cmd`: `1` crear usuario (solo administración local WSL) → `2` generar certificado para dispositivo → `4` visualizar certificado → `5` iniciar sesión → `7` leer recurso y escribir mensaje cifrado → `6` consultar sesión → `8` revocar sesión y confirmar que el token recibe HTTP 401. La opción `9` automatiza el recorrido básico.

El servidor de registro escucha en 8444 con TLS 1.3 de servidor; el gateway de autenticación usa 9443 con TLS 1.3 y **exige certificado de cliente mTLS**. El certificado no sustituye la contraseña: ambas se validan.

## 2. Evidencia real TLS/mTLS

En Ubuntu WSL, con servidores encendidos:

```bash
.venv-wsl/bin/python -m tools.comprobar_tls --sin-access-server --json evidencias/logs/tls_servicios.json
```

Comprobar la versión real y las Cipher Suites reportadas. El servidor rechaza TLS 1.2 y clientes sin certificado; las suites concretas dependen de la negociación OpenSSL, no deben inventarse.

## 3. Wireshark que realmente funcione

**Prueba de 300:** se ejecuta en WSL y sus TCP fluyen por `lo` de Linux. No captures en la Wi-Fi ni en el loopback de Windows. Inicia en una terminal WSL, **antes** de la carga:

```bash
mkdir -p "$HOME/byodsec_capturas"
CAP="$HOME/byodsec_capturas/byodsec_$(date +%Y%m%d_%H%M%S).pcap"
sudo tcpdump -Z "$USER" -i lo -nn -s 0 -U -w "$CAP" 'tcp port 9443'
```

Sin cerrar tcpdump, ejecuta el ensayo desde el cliente. Cuando termine, pulsa `Ctrl+C` y comprueba `tcpdump -nn -r "$CAP" -c 10`. Abre ese fichero ya guardado en Wireshark (Archivo → Abrir), filtro `tcp.port == 9443`. Filtra `tls.handshake.type == 1` para ClientHello, `tls.record.content_type == 23` para Application Data. Si solo ves TCP utiliza Analizar → Decodificar como… TLS 9443. Guardar PCAP y JSON del ensayo; los TCP observados y el resultado de la barrera son evidencias diferentes.

**Prueba Windows → WSL:** usa la opción 5 y 7 del cliente Windows, y captura en WSL si el tráfico se ve en su interfaz; si se hace vía reenvío localhost de Windows/WSL puede requerir capturar en el loopback de Windows. Verificar siempre paquetes reales, no capturas vacías.

## 4. Carga RS3

Menú 10 → prueba 10 → 10/50/100/200/300 identidades. Preparación de logins regulada y reintentos HTTP 500 registrados. El resultado `APROBADO` solo cuenta autenticaciones reales, mensajes en el periodo común, cierres y rechazo de tokens. Valores objetivo: 300/300, errores de mensajes 0, 300 cierres y 300 revocaciones. Ningún reintento se cuenta como otra identidad. `bench/resultados/sesiones_300.json` es el informe de ejecución local. Especificar que son **sesiones REST/TLS mTLS en el mismo WSL**, no 300 túneles IP VPN.

## 5. Seguridad y ataques

Menú 10: comprobación TLS, auditoría de RF5, accesos no autorizados y exportar auditoría. Desde WSL (gateway encendido):

```bash
.venv-wsl/bin/python -m tools.ataques_mtls_real --json evidencias/ataques/mtls_real.json
.venv-wsl/bin/python -m tools.auditar_rf1_rf5_pki --total 300 --json evidencias/logs/auditoria_rf5.json
```

No aportar al informe los CSV de contraseñas, archivos `.key`, certificados privados, logs con tokens o datos personales. Redactar los valores estadísticos y capturas necesarias, ocultando identificadores sensibles.

## 6. RS3b — Comparativa real de rendimiento con y sin TLS/mTLS

**Estado:** el ZIP original no contenía `tools/comparativa_cifrado.py` ni
`tools/servidor_sin_cifrar.py`. Esta versión incluye ambas herramientas y la
opción **10 → 15** del cliente BYODSEC.

1. Arrancar `INICIAR_SERVIDOR_BYODSEC.cmd` y dejarlo abierto. No es necesario
   arrancar manualmente el servidor HTTP sin cifrar: la prueba lo levanta solo
   en `127.0.0.1:9080` y lo apaga cuando termina.
2. Desde `INICIAR_CLIENTE_BYODSEC.cmd` elegir **10 → 15**. Introducir 10 usuarios,
   20 mensajes, 256 bytes, 2 repeticiones. Si sale todo correcto, repetir con
   50, 100, 200, 300 usuarios.
3. La evidencia queda en `bench/resultados/comparativa_10.json` (y archivos
   correspondientes a cada carga). No publicar los ficheros con contraseñas o claves.

También es posible lanzarla desde WSL, en la raíz del proyecto:

```bash
.venv-wsl/bin/python -m tools.comparativa_cifrado --usuarios 10 --mensajes 20 --bytes 256 --repeticiones 2 --json bench/resultados/comparativa_10.json
```

Se prepara **una sesión RF2/mTLS por identidad distinta** antes de iniciar el
cronómetro. Cada usuario envía los mismos mensajes sintéticos ASCII al recurso
HTTPS protegido (`/api/v1/resources/echo`) y al servidor HTTP local (`/echo`).
Ambos calculan SHA-256 y longitud. Las conexiones se mantienen por usuario;
la latencia y el throughput se miden solo durante la comunicación y se alterna
el orden de los escenarios en las repeticiones.

**Criterio de validez:** los dos escenarios deben confirmar TODOS los mensajes;
si hay cualquier error no se calcula el porcentaje de sobrecoste para esa
corrida. No extrapolar números de ejecuciones fallidas.

- **Latencia:** incremento = `(latencia_TLS/latencia_HTTP - 1)*100`.
- **Throughput:** pérdida = `(1 - throughput_TLS/throughput_HTTP)*100`.
- **CPU/RAM:** la herramienta mide el servidor HTTP automáticamente; para
  medir el gateway se puede pasar `--pid-tls PID_GATEWAY_EN_WSL` desde consola.
  Sin PID se reporta `null` (no se inventa el dato). La CPU puede exceder 100%
  si un proceso consume varios núcleos; se expresa respecto a un núcleo.
- **Limitación:** se comparan *rutas REST reales*; en TLS también hay validación
  de sesión y certificado, ausente en HTTP. La diferencia NO es atribuible
  únicamente a la criptografía. No se mide encapsulación VPN IP, ni 300
  máquinas físicas, ni rendimiento de Internet (es loopback WSL2).

Opcionalmente, para mostrar la diferencia de confidencialidad en Wireshark,
realizar una captura autorizada sobre `lo` de WSL con filtro
`tcp port 9443 or tcp port 9080`. Enviar un texto **ficticio** de prueba y
comprobar que el HTTP lo muestra en claro y el HTTPS no. El benchmarking usa
contenido sintético y no contraseñas.

## 7. Objetivo opcional (+10 %) — resistencia comprobable a ataques

No se puede demostrar que sea *imposible* cualquier ataque. Se pueden aportar
pruebas reproducibles de **rechazo de técnicas concretas** en un laboratorio
cerrado y capturas que demuestren confidencialidad en tránsito.

Con el servidor HTTPS real levantado, ejecutar desde el cliente **10 → 13**:

- Cliente sin certificado: servidor deniega canal/autorización.
- Certificado de una CA distinta: rechazo durante TLS.
- Contraseña incorrecta, con certificado legítimo: HTTP 401.
- Intento de usar la contraseña de otro usuario: HTTP 401.
- Token sustraído probado desde otro certificado: HTTP 401.
- Reutilización de token después de logout: HTTP 401.

Evidencia: `evidencias/ataques/prueba_ataques_desde_cliente.json`.

Para probar además la **suplantación de servidor**, entrar en **10 → 16**.
Este escenario levanta en el loopback un servidor TLS impostor firmado por
una CA desconocida y comprueba que el cliente no entrega el mensaje de prueba;
también simula ausencia de certificado y negociación TLS 1.2. Usa certificados
efímeros *diferentes* de los del proyecto. Evidencia:
`evidencias/ataques/tls_opcional.json`.

Capturar el tráfico de una sesión válida en `lo` (puerto 9443) con Wireshark:
comprobar ClientHello/TLS 1.3 y datos cifrados (`Application Data`) y que el
mensaje de prueba no aparece en claro. Usar una captura separada si se necesita
mostrar tráfico HTTP deliberadamente no cifrado en 9080.

**No afirmar:** que se ha realizado una intrusión MITM completa en una red
pública, que el proyecto dispone de un túnel OpenVPN, que ningún ataque
es posible, ni que la ausencia de texto visible por sí sola verifica mTLS.
