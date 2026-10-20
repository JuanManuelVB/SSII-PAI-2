# Demostracion REAL del canal cifrado BYODSEC (camino A)

Este procedimiento NO invoca pytest ni usa mocks. Lanza HTTPS mTLS real, hace
login RF2, recibe un recurso protegido, envia un mensaje y comprueba que RF4
invalida el token. Para demostrar el cifrado deben capturarse paquetes reales.

## Instalacion

Descomprime el ZIP en la raiz de PAI2-STX. Sustituye solo los archivos src/ y
anade tools/demo_canal_en_vivo.py. Revisa cambios si tu rama de trabajo ha
avanzado. No contiene secretos ni certificados privados.

## Terminal 1: Ubuntu WSL

Desde PAI2-STX:

```bash
source .venv-wsl/bin/activate
unset BYODSEC_VPN_REST BYODSEC_VPN_DEFAULT_DENY
python -m src.gateway.ejecutar --port 9443
```

Deja ejecutandose. Este gateway exige TLS 1.3 y certificado cliente mTLS.
No necesita OpenVPN ni el servidor RF1 (8444) para esta demostracion.

## Terminal 2: Ubuntu WSL (captura)

```bash
mkdir -p evidencias/pcap
sudo tcpdump -i any -nn -s 0 -U \
    -w evidencias/pcap/demo_mtls_real.pcap 'tcp port 9443'
```

Mantenlo abierto mientras ejecutas los pasos de Windows.

## Terminal 3: Windows PowerShell, raiz PAI2-STX

```powershell
Remove-Item Env:BYODSEC_VPN_REST -ErrorAction SilentlyContinue
py -m tools.demo_canal_en_vivo --usuario rf5_inv_001
```

Te pedira la contrasena corporativa de RF2 sin mostrarla. El programa hace
una conexion TLS real usando el certificado X.509 ya presente en pki/clients,
verifica el certificado del servidor, negocia TLS 1.3, intenta acceso sin
sesion (HTTP 401), inicia sesion (HTTP 200), consulta el recurso,
envia un mensaje sobre HTTPS, recibe su hash SHA256 desde Ubuntu, hace RF4
y repite acceso con token revocado (HTTP 401).

## Comprobacion visual del cifrado

Deten tcpdump con Ctrl+C en Ubuntu y comprueba:

```bash
sudo tcpdump -nn -r evidencias/pcap/demo_mtls_real.pcap | head -n 20
```

Abre el PCAP con Wireshark y filtra `tcp.port == 9443`; observa `TLSv1.3`
y `Application Data` cifrada. El texto enviado es visible solo en la consola
Windows; NO deberia verse en claro en la captura. Una busqueda orientativa:

```bash
sudo tcpdump -A -r evidencias/pcap/demo_mtls_real.pcap 2>/dev/null | \
  grep -F 'Mensaje corporativo BYODSEC'
```

No debe imprimir nada, pero por si sola esta busqueda NO demuestra TLS:
combinala con la suite/version negociadas por el cliente, el PCAP con paquetes
y los HTTP 200/401 reales. Si el PCAP queda vacio hay que capturar en el
adaptador loopback de Windows (Wireshark/Npcap) o la interfaz concreta de WSL
que recibe ese flujo. Nunca concluir que esta cifrado a partir de 0 paquetes.

La prueba se hace con servidor local WSL2 y cliente Windows; no prueba
conexion remota por una Wi-Fi externa ni tunel OpenVPN.
