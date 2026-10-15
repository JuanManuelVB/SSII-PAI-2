# PAI-2 · Configurar CA para RF1, RF5 y preparación de RF2

## Alcance y precauciones

- **No modifica el código de RF1 ni RF5.** Solo se añaden `src/pki_tools/`, `tests/test_pki_ca.py` y este manual.
- Herramientas de **laboratorio local**, no una PKI productiva. Por compatibilidad con RF1, la clave de CA generada queda sin contraseña y solo debe existir en un equipo controlado, con permisos restringidos. No exportarla, subirla a Git ni compartirla en ZIP.
- Los certificados públicos `*.crt` se pueden distribuir a clientes según necesidad; los archivos `*.key` **nunca**. La CA raíz `ca.crt` debe instalarse como autoridad de confianza solo en el entorno de pruebas, no indiscriminadamente en el sistema de usuarios finales.
- Si ya existen `pki/ca/ca.key` o `pki/ca/ca.crt`, NO ejecutar el generador ni borrar nada: **conservar la CA existente** y verificarla. Cambiar de CA invalida la confianza en certificados anteriores y exige reemisión.
- El ZIP no incluye certificados generados ni ninguna clave privada.

## Instalación Windows (PowerShell)

1. Colocar el contenido del ZIP en la carpeta `PAI2-STX/` de vuestro proyecto, conservando `src/`, `tests/` y `docs/`. No sustituye otros archivos.
2. Abrir PowerShell en **`PAI2-STX/`**, donde está `requirements.txt`.
3. Instalar dependencias si faltan:

   ```powershell
   py -m pip install -r requirements.txt
   ```

4. Generar la CA *una sola vez* en el equipo que firmará certificados:

   ```powershell
   py -m src.pki_tools.cli iniciar-ca
   ```

   Produce `pki/ca/ca.crt` (certificado **público**) y `pki/ca/ca.key` (**CLAVE PRIVADA, no compartir**).

5. Emitir certificado del servidor para pruebas en vuestro propio PC:

   ```powershell
   py -m src.pki_tools.cli emitir-servidor
   py -m src.pki_tools.cli verificar
   ```

   Produce `pki/server/server.crt`, `pki/server/server.key`. El certificado incluye `SAN=DNS:localhost,IP:127.0.0.1` y uso `serverAuth`.

   Si se ejecuta en otro servidor, **antes** de emitir el certificado especificad su DNS/IP reales. Por ejemplo, con dirección de laboratorio:

   ```powershell
   py -m src.pki_tools.cli emitir-servidor --dns vpn.prueba.local --ip 192.0.2.10
   ```

   Estos valores son **ejemplos**; sustituidlos por vuestro DNS/IP. Si ya emitisteis `server.crt`, no lo sobrescribáis a ciegas: haced copia y planificad su reemisión.

6. Como RF1 y RF5 ya buscan esa misma CA, generar **3 certificados de cliente de RF5** (solo después de comprobar la migración SQLite):

   ```powershell
   py -m src.rf5.cli resumen
   py -m src.rf5.cli certificados --limite 3
   py -m src.rf5.cli resumen
   ```

   Con 300 usuarios, `--limite 3` selecciona los primeros por orden alfabético: `rf5_inv_001`, `rf5_inv_002` y `rf5_inv_003` (son tres Investigadores, NO un usuario de cada rol). Las referencias se vinculan en SQLite, tablas `device_pairings` y `rf5_accounts`. Para emitir también los certificados PAS y PDI, podéis ejecutar más adelante `py -m src.rf5.cli certificados` sin límite. RF5 **reutiliza** certificados válidos existentes sin sustituirlos.

7. Comprobar handshake TLS 1.3 *real*, independiente de FastAPI, en `127.0.0.1`:

   ```powershell
   py -m src.pki_tools.prueba_mtls --usuario rf5_inv_001
   py -m src.pki_tools.prueba_mtls --sin-certificado
   ```

   Ambos deben mostrar `PRUEBA OK`: el primero por aceptación con certificado y el segundo porque el servidor rechaza un cliente sin certificado.

8. Ejecutar pruebas automáticas:

   ```powershell
   py -m pytest -q tests/test_pki_ca.py
   ```

## Qué se ha comprobado y qué no

| Comprobación | Cobertura |
|---|---|
| CA raíz X.509 con firma SHA-256, RSA 3072, `CA:TRUE`, `keyCertSign` | `iniciar-ca`, `verificar`, test |
| Certificado de servidor firmado, SAN y `serverAuth` | `emitir-servidor`, `verificar`, test |
| Compatibilidad con RF5/SQLite, 3 certificados `clientAuth` y emparejamientos | `rf5.cli certificados`, test |
| TLS 1.3 con verificación mutua real y rechazo de cliente sin certificado | `prueba_mtls`, test |
| Sesión de aplicación, usuario/contraseña y autorización por dispositivo | **Pendiente de RF2** |
| Revocación de certificados y gestión operativa de CA | **Pendiente**; para producción se requiere ciclo de vida (CRL/OCSP, rotación, etc.) |
| Túnel Road Warrior VPN real | **Pendiente**; mTLS sobre TCP/HTTPS no crea por sí solo una VPN |

## Integración posterior con RF2

- Para RF2 se configurará un servicio HTTPS TLS 1.3 que **requiera certificados de cliente** antes de acceder a las rutas protegidas. El servicio de RF1 para emitir certificados deberá mantener su propio flujo de alta seguro (no puede exigir de entrada un certificado que aún no se ha emitido).
- Comprobar la pertenencia de **serial + huella de la clave pública** a `device_pairings` activo y el `username` de `users`; no basta con que el certificado esté firmado por nuestra CA.
- Después de mTLS, comprobar en la aplicación usuario y contraseña con los hashes `scrypt` existentes, y crear sesión en SQLite. No confiar en un certificado presentado como JSON o en una cabecera HTTP controlable desde Internet.
- Nunca publicar el endpoint FastAPI directamente cuando se use un proxy que le comunique la identidad autenticada: limitarlo a loopback o red privada y eliminar cabeceras de identidad inyectadas desde el cliente.
- En RF4 se invalidará la sesión de aplicación y el cliente cerrará la conexión TLS; el desmontaje de VPN, si existe, es una acción adicional.

## Seguridad y trabajo en Git

En la raíz `PAI2-STX`, asegurar que Git ignora `pki/**/*.key`, `pki/**/*.crt` y `pki/**/*.pem`, además de `pki/clients/rf5/credenciales.csv`. En Windows, comprobar permisos de `pki/ca/ca.key` y **restringir el acceso** a la cuenta que firma certificados. `chmod(600)` no proporciona la misma garantía de ACL en Windows.

**ATENCIÓN:** el ZIP de vuestro proyecto que revisamos incluía un CSV con contraseñas de prueba; no volváis a enviar ni publicar esos secretos. Si se han compartido o versionado, rotad las credenciales antes de un uso serio.

No subir ninguna CA privada a vuestro repositorio. Para trabajo en dos ordenadores, acordad quién custodia `ca.key` y que el resto solo reciba `ca.crt` y los certificados que necesite cada dispositivo, conservando sus claves privadas locales.
