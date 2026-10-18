# Procedimientos de las tareas 6 a 10 · BYODSEC (PAI-2)

Guía paso a paso para completar los puntos 6–10. Para cada uno: **qué pide el
enunciado**, **dónde se ejecuta**, los **comandos exactos** y la **evidencia**
que se genera. Entrega: **27 de octubre, 23:59**.

Convenciones de entorno:
- **[Ubuntu]** = terminal Ubuntu/WSL2, en la raíz del proyecto (`cd` a la carpeta `PAI2-STX`).
- **[Windows]** = PowerShell/CMD con OpenVPN Connect, Wireshark y `py`.
- Arranca el laboratorio una vez con: `bash laboratorio.sh` (instala, arranca y prueba).
- El PID del gateway para medir CPU/RAM está en `~/.local/state/byodsec/gateway.pid`.

---

## Punto 6 · RS2: TLS 1.3 y cifrado

**Enunciado (RS2):** TLS 1.3 con rechazo de SSLv3/TLS 1.0/1.1/1.2; suites AEAD
con PFS (p. ej. `TLS_AES_256_GCM_SHA384` o `TLS_CHACHA20_POLY1305_SHA256`), en
las comunicaciones REST y en el canal de control de la VPN.

**Estado:** la configuración ya está hecha en el código y en
`scripts/3_access_server.sh`. Falta **capturar las evidencias**.

### 6.1 TLS en los servicios REST/gateway  — [Ubuntu]
```bash
python -m tools.comprobar_tls --json evidencias/logs/tls_servicios.json
```
Genera por cada servicio (9443, 8444, 943): versión negociada (`TLSv1.3`),
cipher suite AEAD, **grupo PFS** (`Server Temp Key: X25519`) y el rechazo de
TLS 1.2/1.1/1.0. **Evidencia:** `evidencias/logs/tls_servicios.json`.

### 6.2 TLS del canal de control de la VPN — [Ubuntu, con Access Server]
```bash
sudo /usr/local/openvpn_as/scripts/sacli ConfigQuery | grep -E "tls_version_min|data_ciphers"
sudo bash scripts/manual/exportar_logs_as.sh      # produce as_tls_canal_control.txt
```
Conecta además el túnel (ver punto 9) y revisa `as_tls_canal_control.txt`: debe
aparecer TLS 1.3 en el canal de control y AES-256-GCM/CHACHA20-POLY1305 en el de
datos. **Evidencia:** `evidencias/logs/as_tls_canal_control.txt`.

### 6.3 Prueba negativa en la VPN (opcional pero recomendable) — [Ubuntu]
Con el cliente OpenVPN Community y una copia del `.ovpn`, forzar versión antigua:
```bash
openvpn --config <perfil>.ovpn --tls-version-max 1.2
```
Debe fallar el handshake del canal de control antes de pedir credenciales.

**Justificación para el PDF:** en TLS 1.3 todas las cipher suites son AEAD y usan
intercambio de claves efímero (PFS) por diseño (RFC 8446), de ahí que baste con
registrar la suite y el grupo negociados.

---

## Punto 7 · RS3: prueba de concurrencia (hasta 300)

**Enunciado (RS3):** arquitectura preparada para **300 sesiones simultáneas** y
evaluación cuantitativa (throughput, latencia/RTT y/o CPU/RAM).

**Límite conocido:** OpenVPN Access Server **gratuito admite 2 túneles
simultáneos**; 300 túneles reales exigirían licencia. Esto es una restricción de
**licencia**, no del diseño. Por eso la concurrencia se demuestra contra el
**gateway mTLS** (la pieza que autentica cada acceso), que es lo que el enunciado
pide “preparar”, usando los 300 usuarios RF5. El túnel se mide aparte (punto 8).

### 7.1 Carga 10/50/100/200/300 — [Ubuntu, servicios en marcha]
```bash
GWPID=$(cat ~/.local/state/byodsec/gateway.pid)
for N in 10 50 100 200 300; do
  python -m tools.carga_gateway --usuarios $N --pid "$GWPID" \
      --json bench/resultados/carga_$N.json
done
```
Cada fichero recoge: conexiones exitosas/con error, latencia de login
(media/p50/p95/máx), throughput (ciclos/s) y CPU/RAM del gateway.
**Evidencia:** `bench/resultados/carga_10.json … carga_300.json`.

### 7.2 Gráfica de escalabilidad — [Ubuntu o Windows]
```bash
python -m tools.graficas_rendimiento
```
**Evidencia:** `bench/resultados/grafica_escalabilidad.png`.

> Nota para el PDF: indicar explícitamente que son **sesiones de autenticación
> concurrentes**, no 300 túneles VPN; y que 300 cuentas SQLite no equivalen a 300
> conexiones VPN.

---

## Punto 8 · Rendimiento con y sin VPN

**Enunciado (RS3):** comparación cuantitativa del tráfico **cifrado (VPN)** frente
a **conexiones directas sin cifrar**, sobre el mismo recurso y la misma carga.

### 8.1 Servidor de medida — [Ubuntu, en el destino]
```bash
iperf3 -s           # deja el servidor escuchando (puerto 5201)
```

### 8.2 Medida directa (sin VPN) — [Windows o el cliente]
```bash
py -m tools.medir_cliente --etiqueta directa --host <IP_DESTINO>
```

### 8.3 Medida por VPN — [Windows, con el túnel conectado]
Conecta el túnel en OpenVPN Connect y repite contra la **misma** IP:
```bash
py -m tools.medir_cliente --etiqueta vpn --host <IP_DESTINO>
```
(También existe `bash scripts/manual/medir_iperf.sh <IP> directa|vpn` si prefieres iperf3 directo.)

### 8.4 Gráfica de overhead — [cualquiera]
```bash
python -m tools.graficas_rendimiento
```
Calcula el overhead de throughput y de RTT y dibuja la comparación.
**Evidencia:** `bench/resultados/directa_*.json`, `vpn_*.json`,
`bench/resultados/grafica_overhead_vpn.png`.

> Aviso: entre Windows y WSL2 la ruta “directa” pasa por un switch virtual y no
> representa una red real; es más representativo medir entre **dos equipos en la
> misma Wi-Fi**. Mantener destino, duración (`-t`) y nº de flujos (`-P`) idénticos.

---

## Punto 9 · RS4: Wireshark y auditoría

**Enunciado (RS4):** capturas `.pcap` que demuestren que credenciales y datos
viajan **100 % cifrados** en la interfaz pública; y **registros trazables** de
conexión, desconexión e intentos de acceso no autorizados.

### 9.1 Captura exterior (cifrado) — [Ubuntu, con el túnel conectado]
```bash
sudo bash scripts/manual/capturar_trafico.sh eth0     # o 'any' si WSL2 NAT
```
Mientras captura, haz login RF2 en el menú y conecta el túnel.
**Evidencia:** `evidencias/pcap/vpn_exterior_*.pcap`.

### 9.2 Captura interior (en claro dentro del túnel) — [Ubuntu]
```bash
ip -o link show | grep -E 'as0t|tun'                  # localizar la interfaz
sudo bash scripts/manual/capturar_tunel.sh as0t0
# en otra terminal, mientras captura:
python -m tools.recurso_interno_vpn --host <IP_interfaz_VPN>   # servidor recurso
py -m tools.probar_tunel --fase con-vpn --ip <IP_interfaz_VPN> # cliente
```
**Evidencia:** `evidencias/pcap/tunel_interno_*.pcap`.
En Wireshark: fuera → `tls.handshake.type==2` y `openvpn` (cifrado); dentro →
el HTTP al recurso interno en claro. Contraste = el tráfico iba cifrado por fuera.

### 9.3 Registros de auditoría

La aplicación ya registra automáticamente (sin secretos):
- **Login RF2** (acierto y fallo) y **autorización VPN** → `evidencias/logs/accesos-audit.jsonl` **(nuevo)**
- **Registro RF1** → `evidencias/logs/rf1-audit.jsonl`
- **Cierre RF4** → `evidencias/logs/rf4-audit.jsonl`

Exporta un CSV depurado (apto para el ZIP) y los logs de Access Server:
```bash
python -m tools.exportar_auditoria_csv                 # evidencias/logs/auditoria_accesos.csv
sudo bash scripts/manual/exportar_logs_as.sh           # as_conexiones_vpn.csv, as_auth_fallidos.csv
```
**Evidencia:** `auditoria_accesos.csv`, `as_conexiones_vpn.csv`, `as_auth_fallidos.csv`.

> El empaquetado excluye `*.jsonl` (pueden llevar IPs) pero incluye los `.csv`.
> Por eso se entrega el CSV depurado, no el JSONL en crudo.

---

## Punto 10 · Extra (+10 %): ataques controlados

**Enunciado (extra):** demostrar que la arquitectura (mTLS + TLS 1.3) **resiste e
identifica** ataques de interceptación y suplantación en un entorno controlado.

### 10.1 Ataques contra el gateway real — [Ubuntu, servicios en marcha]
```bash
python -m tools.ataques_vpn_real --json evidencias/ataques/vpn_real.json
```
Comprueba que el gateway **rechaza**: cliente sin certificado, certificado de CA
ajena, contraseña errónea, suplantación por contraseña de otro usuario, token
robado usado con otro certificado y reutilización del token tras logout. Cada
rechazo queda además en `accesos-audit.jsonl` (requisito “identificar”).
**Evidencia:** `evidencias/ataques/vpn_real.json`.

### 10.2 Propiedades TLS en loopback — [Ubuntu]
```bash
python -m tools.ataque_opcional
```
Servidor impostor con CA desconocida, cliente sin certificado y cliente TLS 1.2.
**Evidencia:** `evidencias/ataques/tls_opcional.json`.

### 10.3 Interceptación y reconexión tras revocación — [Windows + Ubuntu, manual]
- **Interceptación:** abre el `.pcap` exterior del punto 9 en Wireshark y muestra
  que el contenido va cifrado; opcionalmente, un proxy delante del gateway debe
  provocar fallo de verificación mTLS.
- **Reconexión tras RF4:** haz logout (menú, opción 4) e intenta reconectar el
  túnel sin nuevo login → debe rechazarse.
- **Revocación de certificado:** `python -m pki.scripts.pki revocar <cert>` y
  repetir el login RF2 → debe fallar. Guarda captura de pantalla y la línea de
  `as_auth_fallidos.csv`.

---

## Resumen de evidencias por punto

| Punto | Evidencia | Generado por |
|---|---|---|
| 6 | `tls_servicios.json`, `as_tls_canal_control.txt` | `comprobar_tls.py`, `exportar_logs_as.sh` |
| 7 | `carga_*.json`, `grafica_escalabilidad.png` | `carga_gateway.py`, `graficas_rendimiento.py` |
| 8 | `directa_*.json`, `vpn_*.json`, `grafica_overhead_vpn.png` | `medir_cliente.py`, `graficas_rendimiento.py` |
| 9 | `*.pcap`, `auditoria_accesos.csv`, `as_conexiones_vpn.csv`, `as_auth_fallidos.csv` | `capturar_trafico.sh`, `capturar_tunel.sh`, `exportar_auditoria_csv.py`, `exportar_logs_as.sh` |
| 10 | `vpn_real.json`, `tls_opcional.json` | `ataques_vpn_real.py`, `ataque_opcional.py` |
