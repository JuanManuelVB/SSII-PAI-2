# RF5: Gestión de usuarios preexistentes (versión con SQLite)

## Qué pide el enunciado

Precargar cuentas institucionales de PDI, PAS e Investigadores con certificados digitales para habilitar las pruebas de concurrencia. El enunciado no define permisos concretos por perfil; el sistema conserva el rol y la futura autorización deberá fijarse por política.

## Persistencia definitiva

A partir de la integración, **SQLite es la única fuente de verdad** para las cuentas. RF1 y RF5 comparten `data/rf1.sqlite3`:

- `users`: usuarios, roles, estados y hashes scrypt (mismo contrato que RF1).
- `device_pairings`: emparejamientos y números de serie de certificados, creados al registrar dispositivos o vincular certificados.
- `rf5_accounts`: metadatos adicionales de cuentas precargadas y dispositivo esperado.

`src/rf5/gestion.py` conserva las utilidades antiguas para las pruebas y la transición, pero **no debe utilizarse para añadir usuarios al proyecto operativo**: esas funciones siguen trabajando sobre el JSON legado. La consola `src/rf5/cli.py` ya ha sido adaptada para operar directamente sobre SQLite. Solo `migrar` consulta el JSON antiguo, una vez.

## Comandos

Desde `PAI2-STX`:

```powershell
py -m pip install -r requirements.txt
py -m src.rf5.cli migrar
py -m src.rf5.cli resumen
py -m src.rf5.cli precargar --total 300
```

La migración no actualiza ni borra cuentas existentes. Los hashes de contraseñas no se recalculan. Repetir la operación con el mismo archivo no duplica datos. Si hay colisiones con cuentas distintas, se aborta la migración del lote.

Para emitir los certificados con la CA **ya configurada por el grupo**:

```powershell
py -m src.rf5.cli certificados --limite 3
py -m src.rf5.cli certificados
```

El script no crea otra CA ni modifica la existente. El certificado y su clave privada se conservan en archivos separados de SQLite, y su asociación se almacena en las tablas compartidas.

## Notas de integración con RF2 y RF4

- RF2 consultará `users` y `device_pairings`, no `usuarios.json`.
- RF2 deberá validar mTLS real y luego el par usuario/contraseña.
- RF4 añadirá sesiones revocables y cerrará el canal/túnel de transporte.
- El registro de 300 cuentas no acredita por sí solo 300 conexiones concurrentes.

## Guía completa y pruebas

Consultar `docs/MIGRACION_RF1_RF5_SQLITE.md`. Las pruebas de esta versión son `tests/test_rf5_sqlite.py` más las existentes.

No publicar contraseñas del CSV de laboratorio, secretos PKI, bases SQLite ni copias históricas del JSON.
