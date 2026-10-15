# RF1 + RF5: una única base de datos SQLite

## Qué se modifica y qué se conserva

- **RF1 SIN CAMBIOS**: `src/server/app.py`, `src/server/usuarios.py` y sus pruebas.
- `src/rf5/cli.py` se actualiza para usar **SQLite como fuente de verdad**.
- Se añade `src/rf5/sqlite_store.py` y se usan las tablas existentes `users` y `device_pairings` de RF1.
- Se añade `rf5_accounts` solo para almacenar los metadatos específicos de la precarga (dispositivo previsto y estado de emisión).
- **No se borran ni sobrescriben registros existentes**. Un conflicto detiene la migración completa.
- El archivo JSON solo se lee mediante `migrar`; el resto de operaciones trabajan con SQLite.

Las tres tablas quedan así:

| Tabla | Datos y responsable |
|---|---|
| `users` (RF1) | `username`, hash scrypt, `role` (`PDI`, `PAS`, `INVESTIGADOR`), `status`, timestamps. Compartida. |
| `device_pairings` (RF1) | Dispositivo, cuenta, huella de clave pública, número de serie, estado. Compartida. |
| `rf5_accounts` (nueva) | Cuenta RF5, dispositivo previsto, estado/ruta/número de serie del certificado. Solo RF5. |

**Las claves privadas NO se guardan en la BD**. En el laboratorio siguen en `pki/clients/rf5/`, fuera de Git. Los certificados se guardan como archivos PEM y sus referencias en SQLite. Es normal que `device_pairings` permanezca vacía hasta que se emitan y vinculen certificados o se realicen registros con RF1.

## Paso a paso (Windows/PowerShell)

1. **Cerrar el servidor antes de la migración** y hacer una copia de seguridad completa de la carpeta del proyecto, especialmente `data/` y `pki/`. No sobrescribir la carpeta `.git`.
2. Descomprimir el parche en el directorio `PAI2-STX/`, conservando la misma estructura. Solo sustituye `src/rf5/cli.py` (del RF5); los demás archivos del parche son nuevos.
3. Entrar en `PAI2-STX` con PowerShell y preparar dependencias:

   ```powershell
   py -m pip install -r requirements.txt
   ```

4. Migrar los 300 registros del fichero `data/usuarios_precargados/usuarios.json` a la **base que usa RF1**:

   ```powershell
   py -m src.rf5.cli migrar
   py -m src.rf5.cli resumen
   ```

   - Si `data/rf1.sqlite3` no existe, se crea con el esquema de RF1.
   - Si existe, se crea antes una **copia SQLite consistente** en `data/backups/`.
   - No hay nuevas contraseñas: se copian los hashes scrypt exactamente como estaban.
   - Se normaliza el rol `Investigador` (JSON) a `INVESTIGADOR` (SQLite).
   - Si ya había un usuario RF1 con el mismo nombre y datos distintos, se detiene la operación y **no sobrescribe** ese usuario.
   - Repetir `migrar` sin alterar los datos no duplica registros.

5. Verificar el resultado. En este ZIP inicial, el resumen esperado es `usuarios_rf5: 300`, `por_rol_rf5: PDI 100, PAS 100, Investigador 100`, `certificados_vinculados: 0`. Si ya había usuarios de RF1, `usuarios_totales` será mayor de 300.
6. **A partir de ahora no volver a usar el JSON para dar de alta usuarios**. Los nuevos comandos RF5 trabajan en la BD:

   ```powershell
   py -m src.rf5.cli precargar --total 300
   py -m src.rf5.cli resumen
   ```

   `precargar` es idempotente y solo crea cuentas que falten respecto al objetivo solicitado. Los secretos temporales nuevos, si los hay, se dejan en `pki/clients/rf5/credenciales.csv` en un entorno de laboratorio, nunca en texto claro en SQLite. El CSV **no es** la base de datos: no lo publiques ni lo subas a Git.

7. Cuando vuestra CA corporativa ya exista (`pki/ca/ca.crt` y `pki/ca/ca.key`), generar/vincular los certificados a la BD:

   ```powershell
   py -m src.rf5.cli certificados --limite 3
   py -m src.rf5.cli certificados
   py -m src.rf5.cli resumen
   ```

   El primer comando sirve para una prueba pequeña. Si todavía no hay CA, el script muestra un error informativo y **no crea otra CA**. Los archivos existentes se verifican y reutilizan, sin sobreescribirlos. Para pruebas reales de BYOD, las claves privadas deben generarse y quedar en los dispositivos; el almacenamiento local de claves de cliente es exclusivamente una simplificación de laboratorio.

8. Pruebas:

   ```powershell
   py -m pytest -q tests/test_rf5_sqlite.py tests/test_rf5.py tests/test_registration_api.py
   ```

## Evitar datos duplicados y filtraciones

- `usuarios.json` **era un archivo de entrada para migración**, pero después de verificar el resultado debe archivarse de manera segura **fuera del repositorio** y retirarse del seguimiento de Git. Desde la raíz `SSII-PAI-2`:

  ```powershell
  git rm --cached PAI2-STX/data/usuarios_precargados/usuarios.json
  ```

  Este comando no elimina el archivo del disco. Para no mantener dos fuentes de verdad en producción, muévelo después a un directorio de respaldo privado **fuera de la carpeta del proyecto** y elimina el original cuando la recuperación esté asegurada.
- El archivo `pki/clients/rf5/credenciales.csv` del ZIP recibido contiene **contraseñas de laboratorio en texto claro**. No lo compartáis en ZIPs ni repositorios. Si este ZIP ha salido del equipo, regenerad esas contraseñas antes de considerar la aplicación segura.
- `data/rf1.sqlite3` y `data/backups/*.sqlite3` están ignoradas por el `.gitignore` del proyecto; aun así, verificad el estado con `git status`. Haced respaldos privados.
- Al migrar, no se crea ningún túnel VPN TLS ni se realiza autenticación mTLS. Son trabajos pendientes de RF2/RS1/RS2.

## Plan técnico para RF2

1. Configurar terminación TLS 1.3 con **mTLS real** en el componente que reciba la conexión, o en un gateway inverso de confianza. Nunca dar por válido un certificado proporcionado en un campo JSON o cabecera HTTP controlada por el cliente. Si hay proxy, bloquear acceso directo a FastAPI y aceptar solo la identidad autenticada por el proxy.
2. Validar CA, vigencia del certificado, uso `clientAuth`, revocación si procede, y relación entre número de serie/huella pública y `device_pairings` con `status='active'`.
3. Crear `POST /api/v1/sessions/login` que, **después** del handshake mTLS, consulte `users`, verifique `password_hash` con el verificador existente de RF1 y solo admita `status='active'`. La identidad del certificado debe corresponder al `username` autenticado.
4. Crear tabla `sessions` en SQLite: `session_id_hash` (o identificador opaco aleatorio tratado con cuidado), `username`, `device_id`, `created_at`, `expires_at`, `revoked_at`. Asociar la sesión al dispositivo certificado y definir expiración y control de permisos.
5. Proteger `GET /api/v1/sessions/me` con sesión válida y certificado concordante. Auditar intentos fallidos sin escribir contraseñas ni tokens.
6. Pruebas: credenciales correctas; contraseña errónea; certificado ajeno/expirado/revocado; rol y usuario bloqueado; reutilización de sesiones sin certificado. **No confundir HTTPS con VPN:** la aplicación necesitará una capa de tunelización si se exige tráfico IP encapsulado.

## Plan técnico para RF4

1. Crear `POST /api/v1/sessions/logout`, accesible únicamente con sesión autenticada.
2. Marcar `revoked_at` de la sesión en SQLite y auditar cierre, sin eliminar el historial de auditoría.
3. El cliente descarta identificador de sesión y **cierra realmente el socket/conexión TLS o el túnel VPN**, según la arquitectura final. Un endpoint HTTP por sí mismo **no destruye** el túnel.
4. Denegar inmediatamente todas las nuevas peticiones asociadas a la sesión revocada; expirarlas también cuando se corte la conexión sin logout.
5. Pruebas: iniciar → acceder → cerrar → intentar acceder de nuevo (401); cierre repetido sin efectos secundarios; desconexión y caducidad.

> Alcance de los documentos: el enunciado define RF2 como `mTLS + credenciales` y RF4 como desmontaje seguro del túnel. Los endpoints y la tabla de sesiones indicados aquí son **propuesta de implementación**, no rutas exigidas literalmente por la profesora.
