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
