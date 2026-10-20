# BYODSEC — Centro de pruebas integrado en el cliente (camino A)

Este parche **no modifica el gateway**, las claves privadas, la base SQLite ni la CA. Usa el gateway TLS 1.3/mTLS y los recursos HTTPS (`/api/v1/resources/*`) que se incorporaron en el parche `BYODSEC_DEMO_CIFRADO_REAL_COMPLETO.zip`.

## Requisitos en el mismo portátil

- Windows: Python y dependencias `requirements.txt`, certificados existentes en `pki/`, `INICIAR_CLIENTE_BYODSEC.cmd`.
- Ubuntu WSL2: `.venv-wsl` con dependencias, `INICIAR_SERVIDOR_BYODSEC.cmd` que arranca el gateway `9443` y el registro RF1 `8444`.
- Para iniciar/parar capturas **desde el menú**: Wireshark para Windows con **Npcap y TShark**. Si no están, la aplicación informa del problema. La captura no requiere conocer las claves TLS.
- Para pruebas de carga: identidades y `credenciales.csv` local de RF5 (¡no adjuntarlo a la entrega!).

## Instalación

1. Haz una copia de seguridad o un commit local, excluyendo las claves privadas.
2. Extrae este ZIP sobre la **raíz de `PAI2-STX`** (no sobre otra carpeta llamada PAI2-STX).
3. Si todavía no tenías el recurso `/api/v1/resources/echo`, instala primero `BYODSEC_DEMO_CIFRADO_REAL_COMPLETO.zip`.
4. Cierra otras instancias del gateway para no ocupar `9443` o `8444`. Doble clic `INICIAR_SERVIDOR_BYODSEC.cmd` y comprueba los dos `[OK]`.
5. Doble clic `INICIAR_CLIENTE_BYODSEC.cmd`, selecciona **10 — Centro de pruebas**.

## Una única prueba real para el profesor

1. En **10 → 1** crea un usuario nuevo y elige PDI/PAS/INVESTIGADOR. Se ejecuta la herramienta administrativa `src.server.usuarios` **localmente dentro de Ubuntu WSL2**, no mediante una API de alta pública. Introduce la contraseña de mínimo 12 caracteres *en el terminal WSL*.
2. En **10 → 2** registra un identificador **nuevo** de dispositivo para ese usuario. RF1 crea una clave RSA-3072 del cliente, solicita y guarda el certificado firmado por la CA.
3. En **10 → 7** selecciona el dispositivo y comprueba su certificado, firma y correspondencia con SQLite.
4. En **10 → 12** haz la demostración guiada: acepta capturar tráfico, elige **Npcap Loopback Adapter**, selecciona tu certificado, escribe la contraseña y escribe un texto **sin datos personales**. Se realizan consultas protegidas, envío real de mensaje (POST HTTPS), comparación SHA-256 y logout con comprobación de `HTTP 401`. Al final se detiene la captura y puedes abrirla en Wireshark.
5. En Wireshark filtra `tcp.port == 9443`, localiza TLS 1.3 / **Application Data** y documenta que el texto enviado no está disponible en claro en las cargas útiles. **No** habilites exportaciones TLSKEYLOGFILE ni incluyas claves privadas, passwords o tokens en las evidencias. La ausencia de texto en claro **por sí sola** no prueba todo TLS: acompáñala de la negociación TLS que muestra 10→8.
6. En **10 → 8** verifica las suites TLS y el rechazo de TLS 1.2/1.1/1.0. En **10 → 9** audita RF5 (300 usuarios). En **10 → 10** puedes hacer carga de 10/50/100/200/300 ciclos, escalando solo cuando el nivel anterior funcione.

## Capturar sin hacer la prueba guiada

- **10 → 5** inicia TShark en una interfaz seleccionada (la opción recomendada es *Npcap Loopback* en Windows/WSL localhost).
- **10 → 3** login; **10 → 4** escribe y transmite el mensaje; **10 → 11** logout.
- **10 → 6** detén la captura y ábrela en Wireshark. El archivo se guarda como `evidencias/pcap/byodsec_mtls_*.pcapng`.
- Si aparece **0 paquetes** la captura no es evidencia válida. La ruta Windows → WSL localhost puede capturarse en una interfaz diferente según la versión de WSL/Npcap: inspecciona las interfaces de TShark, o captura alternativamente con `sudo tcpdump -i any -s 0 -w evidencias/pcap/muestra.pcap 'tcp port 9443'` en Ubuntu mientras repites el envío.

## Funciones del nuevo submenú

| Opción | Prueba |
|---|---|
| 1 | Alta administrativa local de un nuevo usuario corporativo (RF1) |
| 2 | Registro/pareado de dispositivo, emisión de certificado RSA/X.509 (RF1) |
| 3 | Autenticación mutua + usuario/contraseña (RF2) |
| 4 | Mensaje a elección del usuario, petición `POST /api/v1/resources/echo` y verificación SHA-256 |
| 5 | Arrancar captura TShark/Npcap desde Windows (TCP 9443) |
| 6 | Detener, contar tramas y abrir captura en Wireshark |
| 7 | Verificar certificado real y relación con SQLite (RF1) |
| 8 | Verificar TLS 1.3 + rechazo de versiones antiguas (RS2) |
| 9 | Auditar los 300 usuarios, roles y certificados (RF5) |
| 10 | Carga de 10/50/100/200/300 sesiones de RF5, resultados JSON (RS3) |
| 11 | Logout, cierre TLS cliente y revocación HTTP 401 (RF4) |
| 12 | Prueba guiada completa con captura |
| 13 | Seis ataques defensivos reales contra el gateway del propio laboratorio (RS4) |
| 14 | Exportar auditoría a CSV sin secretos (RS4) |

## Seguridad / alcance

- **No se envía el mensaje cifrado manualmente por Python**. HTTPX/OpenSSL negocia TLS 1.3 con mTLS y cifra automáticamente **antes de que el mensaje salga del proceso cliente**. Ubuntu lo descifra para procesarlo, y contesta sobre TLS.
- `SHA-256` sirve para comprobar coherencia de la respuesta, no sustituye al cifrado autenticado proporcionado por TLS.
- El registro de cuenta es **administrativo local**; para un despliegue de varios ordenadores necesitaría una API de administración con autorización fuerte. No se debe exponer un endpoint `/create-user` sin controlar privilegios.
- El modo Camino A es una **pasarela de aplicaciones HTTPS/mTLS**, no una VPN de nivel IP. En RF4 revocamos el token y cerramos el cliente TLS; no se asegura desconexión OpenVPN.
- **RF5 con 300 certificados no equivale a 300 sesiones simultáneas**. La carga es experimental y requiere resultados medidos.
- No compartas el ZIP completo de trabajo con `pki/ca/ca.key`, claves `.key`, `data/rf1.sqlite3` o `pki/clients/rf5/credenciales.csv`.
