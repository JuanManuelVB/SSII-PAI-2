# BYODSEC: REST nativa de Access Server y conexión de compañeros

## Importante antes de instalar

- **Esta implementación requiere OpenVPN Access Server >=3.2, NO OpenVPN Community 2.7**.
- Los tres endpoints de Access Server son `POST /api/auth/login/userpassword`, `GET /api/vpn/status` y `POST /api/vpn/client/disconnect` (todos bajo `/api`). Son los publicados en https://openvpn.net/as-docs/rest-api/ .
- Tu OpenVPN Community instalado y conectado en WSL2 **no se controla con esta API**. No reemplaces archivos del servidor activo hasta decidir migrar.
- Access Server permite **2 conexiones VPN gratuitas simultáneas**. Para tres personas conectadas a la vez, o las pruebas reales de 300, hace falta una suscripción. Para el requisito RS3 de 300 sesiones, podéis conservar Community como banco de carga separado, pero su control de desconexión individual NO será REST nativo.
- Access Server está soportado en Ubuntu 26.04, pero **WSL2 no figura como despliegue oficialmente soportado**; las particularidades de red y firewall deben validarse en el equipo real.
- Access Server administra su propia PKI y usuarios: NO importa automáticamente la CA ni los usuarios SQLite de BYODSEC. Hay que preparar la identidad y la sincronización de autenticación por separado.

## Contenido del parche (solo archivos nuevos)

- `src/vpn_rest_as/client.py`: cliente HTTP oficial de Access Server con verificación TLS; no usa ningún socket de gestión OpenVPN.
- `src/vpn_rest_as/rutas.py`: `GET /api/v1/vpn/me` para el usuario RF2 autenticado, filtrando su estado.
- `src/vpn_rest_as/rf4.py`: variante de RF4 que solicita desconexión REST de TODAS las conexiones del mismo username y luego revoca el token BYODSEC. No se permite especificar otro username en el cuerpo.
- `src/vpn_rest_as/app.py` y `ejecutar.py`: pasarela alternativa que conserva el servidor TLS1.3/mTLS existente; NO cambia `src/gateway/app.py`.
- `tests/test_vpn_rest_as.py`: pruebas HTTP simuladas sin servidor Access Server.

## Preparar la pasarela en el ordenador Windows

Con la aplicación BYODSEC actual instalada, descomprimir respetando la estructura de carpetas y ejecutar:

```powershell
py -m pip install -r requirements.txt
py -m pytest -q tests/test_vpn_rest_as.py
```

La pasarela no puede hablar con Community, por lo que necesita un Access Server configurado y accesible desde Windows por HTTPS.

En PowerShell (ejemplo; **nunca guardes la contraseña en GitHub**):

```powershell
$env:BYODSEC_AS_URL = 'https://127.0.0.1:943'
$cred = Get-Credential   # usuario administrador de Access Server
$env:BYODSEC_AS_ADMIN_USER = $cred.UserName
$env:BYODSEC_AS_ADMIN_PASSWORD = $cred.GetNetworkCredential().Password
$env:BYODSEC_AS_CA_BUNDLE = 'C:\\RUTA\\al-certificado-web-confiable-AS.pem'
py -m src.vpn_rest_as.ejecutar
```

`BYODSEC_AS_URL` debe corresponder al nombre DNS/IP incluido en el certificado web del Access Server. Si el servidor tiene certificado de confianza pública, no hace falta `BYODSEC_AS_CA_BUNDLE`. **No uses `verify=False` ni `curl -k` en producción**.

Desde la consola de BYODSEC, el usuario realizará el mismo login RF2 de siempre y utilizará:

- `GET /api/v1/vpn/me` — estado de SU cuenta, no lista de todos los usuarios.
- `POST /api/v1/sessions/logout` — esta versión solicita POST REST al Access Server y luego revoca el token SQLite.

La identidad del usuario procede de `sesion_autenticada` y de su certificado mTLS, **no** de un nombre suministrado por un cliente.

### Límites de esta primera integración

1. En la API nativa, la desconexión por `users` cierra **todas las sesiones VPN de esa misma cuenta**, no únicamente un dispositivo. Para desconectar un dispositivo habría que conservar `daemon_id/client_id` asociados al dispositivo correcto antes de utilizar `clients`.
2. El endpoint devuelve `vpn_disconnect: requested`, porque no realiza una comprobación posterior de que la conexión desapareció; hace falta verificar la desconexión en una prueba real.
3. Si falla la llamada HTTP al proveedor, RF4 devuelve HTTP 503 sin revocar la sesión web para permitir reintento. Si fallara SQLite después de una desconexión aceptada, podría quedar una sesión web sin revocar. Para una versión de producción hace falta recuperación transaccional (outbox/reintentos) y controles de autorización de acceso.
4. **Desconectar no impide la reconexión automática** si Access Server sigue autorizando la cuenta. Para completar RF4 deben coordinarse los permisos de conexión de Access Server con RF2 (y exigir una nueva autenticación). Esto no viene realizado en el parche.
5. El login de Access Server y RF2 no están integrados automáticamente. Los usuarios de RF5 deben provisionarse en Access Server con nombres acordados, y definir cómo validar sus credenciales. No se puede afirmar cumplimiento total de RF2/RF4 de extremo a extremo hasta verificar esto.

## Cómo conectan los compañeros a UN ÚNICO servidor (recomendado)

### Caso 1: mismos Wi-Fi/LAN

1. El ordenador con Ubuntu WSL2 es el **servidor**; los compañeros solo necesitan un cliente OpenVPN Connect/OpenVPN GUI en Windows, no instalar WSL.
2. Crear **una cuenta diferente para cada compañero** en Access Server con la autenticación prevista y generar **su propio perfil individual `.ovpn`**. No compartir perfiles ni claves privadas entre personas.
3. Abrir en el ordenador anfitrión la **Web UI de clientes** `https://DIRECCION_DEL_SERVIDOR:943/` y facilitar a cada compañero la URL segura (nunca usuario/clave de administrador). Cada uno inicia sesión y descarga su perfil de cliente. También se puede generar el perfil mediante la REST oficial una vez configurada.
4. En Windows, el compañero importa su perfil `.ovpn` en OpenVPN Connect e inicia la conexión. Comprobar con el servidor que obtiene una IP VPN y alcanza un recurso de prueba.
5. Para que los otros ordenadores alcancen un WSL2 servidor, **NO sirve la IP NAT 172.23.x.x que se usó desde el mismo Windows**. En Windows 11 22H2+ se puede estudiar `networkingMode=mirrored` en `%UserProfile%\\.wslconfig`; reiniciar con `wsl --shutdown` y permitir exclusivamente puertos requeridos mediante Firewall de Windows y Firewall Hyper-V (normalmente UDP 1194 y TCP 943; comprobar la configuración real del Access Server). Si WSL no es accesible desde LAN, mover el servidor a una VM Linux dedicada será más predecible.
6. Las cuentas de un Access Server gratuito tienen **solo dos plazas concurrentes**. Los tres debéis entrar por turnos para probar sin licencia, o disponer de plan para 3+.

### Caso 2: compañeros desde otra red / Internet

1. Primero conseguir que funcione en LAN y verificar certificados.
2. Si el servidor está en casa, harían falta un destino alcanzable (IP pública/DNS o conexión de red privada autorizada), configuración de firewall y, según el caso, redirección de los puertos VPN del router. La dirección NAT local `172.23.x.x` NO es accesible desde Internet.
3. **No publicar sin protección el panel de administración ni una API con credenciales de administrador**. Controlar el acceso al puerto web, usar TLS válido, contraseñas fuertes y preferiblemente MFA.
4. La opción más reproducible para una práctica con clientes remotos es una VM/servidor Linux con IP alcanzable, o una red privada de laboratorio, en vez de depender de WSL + router doméstico.

## Alternativa si NO queréis licencias

Seguir con OpenVPN Community, que ya funciona en vuestro WSL, y usar API REST **en toda la aplicación BYODSEC**. Sin embargo, el proceso Community debe recibir órdenes a través de su interfaz de administración u otro mecanismo local. Por tanto, no puede afirmarse que todo el control interno de OpenVPN sea REST puro: Community no proporciona endpoints REST nativos de consulta y desconexión.

## Fuentes oficiales

- REST API: https://openvpn.net/as-docs/rest-api/
- Ubuntu Access Server: https://openvpn.net/as-docs/v3/ubuntu.html
- Instalación: https://openvpn.net/as-docs/v3/installation.html
- Precio (dos conexiones gratuitas): https://openvpn.net/access-server/pricing/
- Redes WSL2: https://learn.microsoft.com/es-es/windows/wsl/networking
