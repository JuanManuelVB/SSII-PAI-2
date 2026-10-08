# RF5 — Gestión de Usuarios Preexistentes y Perfiles de Acceso

## Alcance estricto del enunciado

El requisito funcional RF5 (página 4 del enunciado) pide **precargar cuentas corporativas de PDI, PAS e Investigadores con sus certificados emitidos** para posibilitar pruebas de carga y concurrencia. **No define una matriz concreta de permisos por rol**. Por eso este módulo almacena los perfiles sin inventar qué recursos puede consultar cada uno; la política de autorización se acordará con el grupo.

## Independencia respecto al trabajo del compañero

- **No** cambia `src/server/app.py` ni los módulos, tests, configuraciones o certificados existentes de RF1–RF4.
- Reutiliza *el contrato ya implementado* por RF1: el servidor lee `data/usuarios_precargados/usuarios.json` y necesita `username`, `password_hash` (scrypt) y `status = "active"`.
- Para gestionar RF5 añade exclusivamente `src/rf5/` (tres archivos), `tests/test_rf5.py`, este documento y `pki/clients/rf5/.gitignore` (seis archivos nuevos en total).
- El script de precarga **actualiza `usuarios.json` solo cuando se ejecuta**, y añade cuentas RF5 respetando todos los registros previos. El ZIP entregado mantiene intacto ese JSON; debes coordinar cuándo ejecutar el comando en el repositorio compartido.
- El paso de certificados depende de **la CA del compañero**, `pki/ca/ca.crt` y `pki/ca/ca.key`. No genera una CA distinta ni modifica dichos archivos. Reutiliza las claves y certificados ya emitidos si son válidos.

## Preparar entorno

Desde la carpeta `PAI2-STX`:

```bash
python -m pip install -r requirements.txt
python -m src.rf5.cli precargar --total 300
python -m src.rf5.cli resumen
```

La precarga crea **100 PDI, 100 PAS y 100 Investigadores** de prueba (300 en total). Usa nombres `rf5_pdi_001`, `rf5_pas_001`, `rf5_inv_001` y así sucesivamente, `status=active`, identificador de dispositivo y hash con scrypt compatible con RF1. Para probar primero con tres usuarios, ejecutar `python -m src.rf5.cli precargar --total 3`. Ejecutarlo de nuevo **no duplica usuarios ni sustituye contraseñas existentes**.

La lista de contraseñas temporales se guarda **solo en local** en `pki/clients/rf5/credenciales.csv`, con permisos restringidos al propietario cuando el sistema lo permite. Ese directorio ignora todo su contenido generado en Git. **No subas ni envíes ese CSV, claves privadas, ni logs con credenciales**. Los hashes del JSON no son contraseñas en claro. Protege también ese JSON, que contiene datos de identidad y verificadores de contraseña; úsalo exclusivamente en entorno docente.

### Certificados X.509 (cuando la CA esté configurada)

```bash
python -m src.rf5.cli certificados --limite 3
python -m src.rf5.cli certificados
python -m src.rf5.cli resumen
```

Emite un certificado **TLS de cliente** por cuenta y un par RSA-2048 bajo `pki/clients/rf5/`. Certificados firmados por la CA que ya exista, con nombre de dispositivo (`CN`), usuario (`OU`), `ExtendedKeyUsage=clientAuth` y validez no superior a la CA. Registra en el JSON un número de serie y la ruta del certificado. Repetir el comando valida y reutiliza el material existente; no lo sobrescribe.

**Nota de seguridad:** guardar una clave privada de cliente en el propio servidor es únicamente un recurso para el laboratorio y el simulador de carga. En un BYOD real, la clave privada debe generarse y permanecer en el dispositivo y no transferirse al servidor. La CA del laboratorio requiere una clave no cifrada para este script; en una implantación real se usaría un servicio de emisión seguro o HSM.

## Integración (sin editar RF1–RF4 por tu cuenta)

Tu compañero debe leer o respetar `role`, `device_id`, `certificate_serial` y `certificate_path` de las cuentas RF5 cuando integre su inicio de sesión y gateway. La función independiente `src.rf5.gestion.consultar_perfil(username)` permite recuperar únicamente el perfil activo y metadatos (sin hash ni contraseña) para facilitar esa integración. RF1 ya puede verificar las contraseñas precargadas mediante el formato de hash utilizado. Para confiar en el certificado en el handshake **mTLS real**, el gateway deberá validar la cadena hacia la CA, la vigencia y la asociación del certificado con el usuario/dispositivo; que un fichero exista no demuestra que la conexión esté protegida.

La carga de 300 registros **no equivale a** haber soportado 300 sesiones simultáneas: RS3 exige medir concurrencia y rendimiento sobre la implementación completa del gateway.

## Pruebas independientes

```bash
python -m pytest -q tests/test_rf5.py
```

Cubren precarga de los tres perfiles, compatibilidad scrypt con el RF1 que ya está en el ZIP, preservación de usuarios ajenos, ejecución repetida sin duplicados, reparto exacto de 300 registros, protección ante JSON malformado, generación/validación de certificados con una CA temporal de prueba y error limpio si aún no hay CA configurada.

**Comprobación antes de copiar al repositorio compartido:** el ZIP `PAI2_RF5_SOLO_ARCHIVOS_NUEVOS.zip` contiene únicamente los seis archivos nuevos descritos arriba (uno de ellos es el `.gitignore` del RF5); no contiene ni reemplaza archivos existentes de tu compañero ni la carpeta `.git`.
