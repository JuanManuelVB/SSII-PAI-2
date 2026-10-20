# BYODSEC — Corrección RS3: respuestas 500 bajo 300 autenticaciones

## Qué ha mostrado tu ensayo

300 cuentas solicitadas, 241 sesiones válidas en barrera. Los 59 fallos son respuestas **HTTP 500 del gateway**: 28 en challenge y 31 en login. No son 59 claves incorrectas (eso debería dar 401). La causa concreta del HTTP 500 deberá contrastarse con los traceback del servidor; la concurrencia en SQLite es una hipótesis relevante.

## Qué cambia el parche

1. `src/rf2/sesiones.py`: elimina la inicialización del esquema SQLite de CADA solicitud /challenge. Las tablas siguen creándose una vez al arrancar el servidor (FastAPI lifespan). No se borran usuarios/sesiones.
2. `src/common/base_datos.py`: establece timeout/busy_timeout SQLite de 30 segundos para esperar cuando otro escritor posee el bloqueo. No se cambia journal_mode ni estructura de la base de datos; adecuado como primer remedio cuando el archivo está en OneDrive/NTFS.
3. `tools/carga_300_sesiones.py`: escalona también los logouts al terminar la ventana simultánea y registra sus errores. Admite por defecto **12 autenticaciones en paralelo** durante la preparación; las sesiones autenticadas siguen activas y *TODAS* pasan simultáneamente al periodo común de mensajes, sin límite de 12 en esa fase. No se reduce el objetivo de 300 sesiones. Se añade `--concurrencia-auth` para graduar el pico inicial.

## Instalación

- Cierra los servidores BYODSEC con Ctrl+C y espera al cierre; no lances dos instancias en 9443.
- Haz copia de los 3 archivos que se sustituyen. Extrae el ZIP en la raíz de PAI2-STX, conservando carpetas.
- **Arranca de nuevo** `INICIAR_SERVIDOR_BYODSEC.cmd` para que tome la nueva conexión SQLite y cambio de /challenge.
- Abre el cliente y ve a `Pruebas y Wireshark → 10 Mantener hasta 300 sesiones mTLS` (utiliza la herramienta actualizada, por defecto 12 logins en paralelo).

## Prueba progresiva

Desde el menú: primero 50 usuarios, luego 300; usa un periodo de 30 segundos para la primera prueba, 120 segundos si funciona. En WSL desde PAI2-STX:

```bash
source .venv-wsl/bin/activate
python -m tools.carga_300_sesiones --usuarios 50 --duracion 10 --preparacion 360 --concurrencia-auth 12 --json bench/resultados/rs3_50_fix.json
python -m tools.carga_300_sesiones --usuarios 300 --duracion 30 --preparacion 600 --concurrencia-auth 12 --json bench/resultados/rs3_300_fix.json
```

IMPORTANTE: desde el menú integrado se mantiene el límite 360 s de preparación. Si necesitas 600 s, ejecuta por terminal como en el ejemplo. **El tiempo de preparación no cuenta como periodo de sesiones simultáneas:** el periodo común comienza solo después de autenticar las 300.

## Aprobación

Debe aparecer `Barrera: 300/300 sesiones autenticadas` y al finalizar el informe JSON `resultado: APROBADO`, con 300 completados, 0 errores de mensajes, 300 logouts y 300 rechazos de tokens reutilizados. No confundir sesión de aplicación con 300 túneles VPN ni con equipos físicos.

Si vuelve a aparecer `HTTP 500`, revisa el traceback en la ventana del gateway. Errores `sqlite3.OperationalError: database is locked` confirmarían contención de SQLite; otros tipos exigen corregir otra causa. No publiques claves, passwords, CSV, tokens ni base de datos.
