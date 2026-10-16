# BYODSEC — Interfaz interactiva de consola (RF1 / RF2 / RF4 / RF5)

## Instalación

Descomprime los archivos del parche dentro de **PAI2-STX**. No sobrescribas código existente.

```powershell
py -m pip install -r requirements.txt
py -m pip install -r requirements-interfaz.txt
```

## Preparación

Los servidores son procesos independientes; la interfaz es únicamente un cliente.

**Terminal 1 — Gateway protegido RF2/RF4 (TLS 1.3 + mTLS obligatorio)**

```powershell
py -m src.gateway.ejecutar
```

**Terminal 2 — Registro RF1 (opcional; solo para opción 1 del menú)**

```powershell
py -m src.gateway.ejecutar_registro
```

**Terminal 3 — Menú**

```powershell
py -m src.client.interfaz
```

En caso de utilizar un gateway externo:

```powershell
py -m src.client.interfaz --url https://vpn.ejemplo:8443 --registro-url https://vpn.ejemplo:8444 --ca pki/ca/ca.crt
```

El hostname debe coincidir con los SAN del certificado del servidor; no se desactiva la verificación TLS.

## Uso del menú

| Opción | Acción | Lo que realmente comprueba |
|---|---|---|
| 1 | Alta de dispositivo RF1 | Registro real en `:8444`, emisión de certificado, clave RSA privada generada localmente |
| 2 | Iniciar sesión RF2 | mTLS, desafío firmado, usuario y contraseña, token en memoria |
| 3 | Consultar sesión RF2 | `GET /api/v1/sessions/me` con token y mismo certificado TLS |
| 4 | Logout RF4 | `POST /logout`, cerrar cliente HTTP/TLS y nuevo `GET /me` con token anterior → 401 |
| 5 | Usuarios RF5 | Estadísticas locales de SQLite, sin mostrar contraseñas |
| 6 | Auditoría | Lectura local de eventos RF1 y RF4 desde `evidencias/logs/` |
| 7 | Demo completa | Login → consulta → logout → reutilización rechazada |
| 8 | Certificados | Lista de pares `.crt` + `.key` locales disponibles |
| 0 | Salir | Ofrece cerrar sesión RF4; si no, solo descarta token local |

Para certificados precargados:

```powershell
py -m src.rf5.cli resumen
py -m src.rf5.cli certificados --limite 3
```

La aplicación descubre los certificados emitidos en `pki/clients/rf5/*.crt` y `pki/clients/*.crt` cuando existe su clave `.key`. En RF5, usa la contraseña que corresponda al usuario en el **CSV privado** `pki/clients/rf5/credenciales.csv` (no copies ese CSV al repositorio).

La opción 1 es para un dispositivo **nuevo**, no para re-registrar un dispositivo RF5 ya emparejado. Si el servidor de registro devuelve 409, el dispositivo ya existe.

## Pruebas

```powershell
py -m pytest -q tests/test_interfaz_consola.py
py -m pytest -q
```

En la demostración automática, los resultados correctos son `200 → 200 → 200 → 401`, donde el último `401` demuestra el rechazo del token revocado.

## Seguridad y límites

- **Nunca** muestra el token de sesión, claves privadas ni contraseñas. Las contraseñas se piden con `getpass`.
- Se verifica la CA y el nombre del servidor; el cliente solo acepta TLS 1.3.
- El cierre es real en SQLite porque llama al endpoint RF4 del gateway; el cliente descarta token y conexiones después de confirmación.
- Si hay un error de red durante el cierre, **no afirma** que el servidor haya revocado la sesión.
- No se almacena el token en disco, ni se intenta falsificar el certificado TLS enviando cabeceras.
- La clave privada del registro RF1 se guarda sin contraseña para compatibilidad con el laboratorio. Se recomienda endurecer esto en producción.
- **No implementa ni desmonta una interfaz VPN TUN/TAP real**. Es una demostración funcional HTTPS/mTLS y de la capa de sesiones. No la presentes como túnel VPN ya implementado.
- La opción de auditoría y RF5 asume que la interfaz se ejecuta en el mismo proyecto/ordenador que SQLite y los logs.
- La CA privada `pki/ca/ca.key`, `*.key`, `credenciales.csv`, archivos `.sqlite3` y logs no deben subirse a Git.

## Commit independiente (sin ramas)

```powershell
git add src/client/interfaz.py src/client/servicio_consola.py requirements-interfaz.txt docs/INTERFAZ_CONSOLA.md tests/test_interfaz_consola.py
git diff --cached --stat
git commit -m "Agregar consola interactiva BYODSEC"
git pull --rebase origin main
git push origin main
```
