# RF2 + RF4: implementación e instrucciones (PAI-2)

## Alcance exacto

Se han **añadido nuevos archivos**, sin editar `src/server/app.py`, `src/server/tls.py`, `src/common/base_datos.py` ni RF5. La integración reutiliza las tablas `users` y `device_pairings` en `data/rf1.sqlite3` y añade dos tablas: `login_challenges` y `sessions`.

- **RF2:** autenticación TLS 1.3/mTLS, validación de un certificado ya emparejado en RF1/RF5, contraseña `scrypt`, desafío firmado con clave privada, emisión de token aleatorio y sesiones en SQLite.
- **RF4:** revocación persistente del token presentado, evento de auditoría sin credenciales, solicitud de cierre del transporte HTTPS y rechazo de sesiones cerradas.
- **Límite pendiente:** todavía no existe una VPN con interfaz virtual/túnel TUN. Cerrar una sesión y un socket HTTPS no equivale a desmontar un túnel Road Warrior. Cuando la persona responsable de la VPN implemente el cliente/túnel, debe añadir a su cliente el desmontaje de la interfaz y limpieza del estado de VPN en el cierre.

## 1. Instalación sobre el proyecto existente

Extraer el parche **dentro de `PAI2-STX`**. Mantener los archivos que pertenecen a RF1/RF5 y la CA ya generada. En PowerShell, situado dentro de `PAI2-STX`:

```powershell
py -m pip install -r requirements.txt
py -m pytest -q tests/test_rf2_rf4.py tests/test_rf2_rf4_mtls_integracion.py tests/test_rf2_rf5.py
```

Las pruebas crean CA, certificados y SQLite **temporales**, no afectan la base real ni sustituyen la CA del grupo.

## 2. Preparar un usuario de prueba

Para trabajar con usuarios de RF5 (si ya están precargados, omitir el primer comando):

```powershell
py -m src.rf5.cli precargar --total 300
py -m src.rf5.cli certificados --limite 3
py -m src.rf5.cli resumen
```

El usuario `rf5_inv_001` será uno de los primeros certificados emitidos. Sus rutas típicas:

- `pki/clients/rf5/rf5_inv_001.crt`
- `pki/clients/rf5/rf5_inv_001.key`
- Identificador: `rf5-inv-001-dev01`

La contraseña está **solo en el CSV privado local** `pki/clients/rf5/credenciales.csv`; no la imprimas ni la subas al repositorio. Debe existir previamente `pki/ca/ca.crt`, `pki/ca/ca.key`, `pki/server/server.crt` y `pki/server/server.key`.

## 3. Arrancar el servidor de acceso protegido

```powershell
py -m src.gateway.ejecutar
```

Escucha por defecto en `https://localhost:8443` (TLS 1.3 obligatorio y certificado cliente requerido). **No** arrancar este servicio como `uvicorn src.gateway.app:app`, ya que el arranque específico es el que instala TLS y expone al módulo la identidad real del certificado verificado por el socket. Fuera de ese arranque, RF2/RF4 rechazan las peticiones por defecto.

Es posible indicar otro host/puerto:

```powershell
py -m src.gateway.ejecutar --host 127.0.0.1 --port 8443
```

Para que un dispositivo SIN certificado pueda registrarse en RF1, abrir **otra terminal** y arrancar el servicio de alta separado (HTTPS/TLS 1.3 con autenticación del servidor, sin exigir aún certificado cliente):

```powershell
py -m src.gateway.ejecutar_registro
```

RF1 atiende en `https://localhost:8444`. La autenticación por credenciales de RF1 es responsabilidad de su módulo original; este arranque no lo modifica. En una instalación real habría que añadir control de intentos, autorización de altas y políticas de seguridad del proceso de enrolamiento.

## 4. Probar login, consulta y cierre completos

En otra terminal, dentro de `PAI2-STX`, ejecutar:

```powershell
py -m src.client.ejemplo_login --username rf5_inv_001 --device-id rf5-inv-001-dev01 --cert pki/clients/rf5/rf5_inv_001.crt --key pki/clients/rf5/rf5_inv_001.key
```

El cliente pedirá la contraseña del CSV de laboratorio **sin mostrarla**, y realizará:

1. **POST `/api/v1/sessions/challenge`**: pedir desafío aleatorio (90 s, un solo uso).
2. **POST `/api/v1/sessions/login`**: presentar credenciales y un certificado cliente; demostrar posesión de su clave privada firmando `PAI2-RF2-LOGIN\\n<nonce>\\n<username>\\n<device_id>`; comparar certificado de la petición con el del socket TLS; comprobar CA, vigencia, revocaciones registradas, emparejamiento activo y contraseña; crear sesión de 30 minutos.
3. **GET `/api/v1/sessions/me`**: consultar el perfil protegido con un `Authorization: Bearer <token>`. Se valida que ese mismo certificado sigue presente en la conexión TLS.
4. **POST `/api/v1/sessions/logout`**: el servidor revoca el token en SQLite, escribe evento JSONL y añade `Connection: close` para HTTPS/1.1; el cliente cierra su socket TLS.
5. **GET `/api/v1/sessions/me`** de nuevo: debe responder **HTTP 401**.

El servidor **solo almacena SHA-256 del token**, no el token original. Si la cuenta o el dispositivo quedan desactivados, se rechaza la sesión aunque no haya expirado.

## 5. Archivos añadidos y responsabilidades

```text
src/rf2/autenticacion.py            Credenciales, firma y certificado
src/rf2/sesiones.py                Desafíos y sesiones SQLite
src/rf2/rutas.py                   Endpoints /challenge, /login y /me
src/rf4/cierre.py                  UPDATE revocable del token
src/rf4/auditoria.py               Auditoría sin claves ni contraseñas
src/rf4/rutas.py                   Endpoint /logout
src/gateway/app.py                 API integrada, sin editar RF1
src/gateway/protocolo_mtls.py      Datos del certificado desde el socket TLS
src/gateway/ejecutar.py            Arranque TLS1.3/mTLS con Uvicorn
src/gateway/ejecutar_registro.py   Alta RF1 separada sobre HTTPS TLS1.3
src/client/ejemplo_login.py        Demostración extremo a extremo
```

## 6. Evidencias que podéis conservar

- Salida de `pytest` y resultados 200 -> 200 -> 200 -> 401 en la demostración.
- Conexión TLS rechazada sin certificado (prueba `test_rf2_rf4_mtls_integracion.py`).
- Conexión rechazada usando **otro** certificado con un token robado.
- En SQLite, `SELECT username, device_id, revoked_at FROM sessions;` (no seleccionar tokens ni hashes en capturas públicas).
- En `evidencias/logs/rf4-audit.jsonl`, evento `session_closed`, con fecha, usuario y dispositivo. El archivo es local, ignorado por Git.
- Captura Wireshark de la interfaz pública: en TLS 1.3 el contenido de la aplicación viaja protegido; no debe verse una contraseña legible.

## 7. Limitaciones y futuras correcciones de seguridad

- **VPN:** falta implementar una interfaz real de VPN (TUN/TAP, rutas, forwarding, retirada de la interfaz al desconectar). No afirmar que ya se desmonta un túnel completo.
- **PKI:** los certificados actuales de la herramienta de laboratorio no incluyen `AuthorityKeyIdentifier` en certificados emitidos. Clientes con modo de validación X.509 estricto pueden rechazarlos. El cliente demostrador mantiene verificación de CA, firma y hostname usando `SSLContext(PROTOCOL_TLS_CLIENT)`, sin habilitar el modo estricto. Conviene que el responsable de PKI regenere certificados incorporando `AuthorityKeyIdentifier` y `SubjectKeyIdentifier` antes de pasar a producción.
- **CRL:** `revoked.json` se consulta en cada login y `device_pairings.status` se comprueba en cada petición. Una revocación por lista después de un login debe ir acompañada de desactivación del dispositivo y/o invalidación de sesiones; el contexto mTLS actual del compañero todavía no carga una CRL firmada en el handshake.
- **Límites del laboratorio:** faltan limitación de intentos, rotación de claves, controles de distribución BYOD de claves, perfiles de permisos por recurso, métricas de 300 conexiones y pruebas específicas del túnel.
- **Dependencia de Uvicorn:** el adaptador de certificados usa el protocolo HTTP/1.1 interno de Uvicorn. Se ha probado con Uvicorn 0.48; si se cambia su versión, ejecutar la prueba de integración de TLS antes de desplegar.
- **Secretos:** nunca subir `.key`, `credenciales.csv`, bases `.sqlite3` ni archivos de logs. El parche no contiene ninguno de ellos.

## 8. Commit sin branches

```powershell
git status --short
git add src/rf2 src/rf4 src/gateway src/client/ejemplo_login.py tests/test_rf2_rf4.py tests/test_rf2_rf4_mtls_integracion.py tests/test_rf2_rf5.py docs/RF2_RF4_GUIA.md
git diff --cached --stat
git commit -m "Implementar RF2 y RF4 con sesiones SQLite y mTLS"
git pull --rebase origin main
git push origin main
```

Siempre trabajar desde `main` limpio y coordinarse con los compañeros antes de hacer `push`. No se han alterado módulos previos, para minimizar conflictos.
