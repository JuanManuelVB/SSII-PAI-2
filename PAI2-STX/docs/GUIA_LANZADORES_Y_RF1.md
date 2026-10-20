# BYODSEC — Lanzadores y comprobación real de certificados RF1

## Instalación (una sola vez)

Extrae el contenido de este ZIP **en la raíz de PAI2-STX** (la carpeta donde ya existe `src/`).
El ZIP no sustituye archivos existentes del proyecto: solo añade dos `.cmd`, un `.sh`, un verificador y esta guía.
Necesita el código del parche Camino A y las dependencias Python que ya utilizas.
No contiene ni crea contraseñas, claves privadas o cuentas.

## Cada vez que quieras utilizar el sistema

1. Doble clic `INICIAR_SERVIDOR_BYODSEC.cmd` (primero). Espera los dos mensajes `[OK]`.
   - Gateway HTTPS/TLS 1.3 con mTLS `https://localhost:9443`.
   - Registro HTTPS/TLS 1.3 RF1 `https://localhost:8444` (sin certificado de cliente antes del alta).
2. Doble clic `INICIAR_CLIENTE_BYODSEC.cmd` (después). Verás el menú.
3. Deja abierta la ventana del servidor durante las pruebas. Para parar pulsa Ctrl+C en esa ventana.

Se arranca **Ubuntu WSL2 como servidor y Windows como cliente, en el mismo portátil**. 
**No** se utiliza VirtualBox ni OpenVPN. Si otro proceso ocupa los puertos 9443/8444,
ciérralo antes; el lanzador NO mata servicios anteriores.

## Emisión real de certificado (RF1)

1. En el cliente elige **[1] RF1 Registrar dispositivo**.
2. Usuario: por ejemplo `rf5_inv_001` (debe existir y estar activo en tu BD).
3. Dispositivo NUEVO: por ejemplo `rf1_demo_01` (cada ejecución usa uno diferente).
4. Escribe la contraseña REAL del usuario (no se imprime ni se guarda en logs).
5. Debe mostrar `HTTP 201 · Certificado RF1 emitido`.
6. Aparecen los archivos:
   - `pki/clients/rf1_demo_01.crt` (certificado público X.509)
   - `pki/clients/rf1_demo_01.key` (clave privada local, NUNCA mostrar ni compartir)
7. En Windows PowerShell, desde PAI2-STX, verifica con:
   `py -m tools.verificar_certificado_real --dispositivo rf1_demo_01`
   Esperamos `CERTIFICADO VALIDO Y EMPAREJADO`, con la firma de la CA, número de serie,
   vínculo a SQLite y correspondencia de clave verificados.
8. Elige **[8] Inspeccionar certificados**: comprobarás que aparece el nuevo dispositivo.
9. Elige **[2] Iniciar sesión**, escoge `rf1_demo_01` e introduce su contraseña.
   Esperamos `HTTP 200`.
10. Elige **[9] Recurso corporativo TLS**: GET y POST reales HTTPS (HTTP 200),
    verifica SHA-256 del mensaje recibido desde Ubuntu.
11. Elige **[4] Cerrar sesión**: logout HTTP 200 y rechazo posterior HTTP 401.

### ¿Cómo demostrar el cifrado realmente?

Captura el tráfico durante los pasos 9 y 10, desde otro Ubuntu WSL:

```bash
cd '/mnt/c/Users/Pablo/OneDrive/Escritorio/US/4º/1º CUATRIMESTRE/SSII/PAIs/SSII-PAI-2/PAI2-STX'
mkdir -p evidencias/pcap
sudo tcpdump -i any -n -s 0 -w evidencias/pcap/rf1_login_real.pcap 'tcp port 9443 or tcp port 8444'
```

Para terminar, Ctrl+C y abrir la captura con Wireshark. Si no hay paquetes, usa
Npcap Loopback Adapter en Wireshark Windows; no presentes una captura vacía.
En `9443` hay mTLS: TLS 1.3 y autenticación del dispositivo; en `8444` el
servidor usa TLS 1.3 para registrar el dispositivo SIN certificado de cliente
previo, algo necesario para el primer emparejamiento.

Para revisar atributos del certificado también puedes usar, desde Ubuntu WSL:

```bash
openssl x509 -in pki/clients/rf1_demo_01.crt -noout -subject -issuer -dates -serial -ext extendedKeyUsage
openssl verify -CAfile pki/ca/ca.crt -purpose sslclient pki/clients/rf1_demo_01.crt
```

## Qué grabar o capturar para el profesor

- [1] `HTTP 201` y nombre del dispositivo (RF1).
- Salida del verificador `[OK]` y `CERTIFICADO VALIDO Y EMPAREJADO`.
- [2] login `HTTP 200` con el dispositivo recién emitido (RF2).
- [9] envío y respuesta de datos con hash SHA-256, servidor HTTPS (recurso real).
- Captura Wireshark TLS 1.3 con paquetes visibles, contenido no legible.
- [4] logout `HTTP 200` seguido de petición rechazada `HTTP 401` (RF4).

No fotografíes la contraseña, tokens ni el contenido de archivos `.key`.
Si no apareciesen los usuarios iniciales, no regeneres la CA: comprueba la BD
actual o el procedimiento de precarga RF5 antes de emitir nuevos certificados.
