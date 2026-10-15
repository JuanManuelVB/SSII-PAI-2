# RF5 — Usuarios preexistentes en SQLite

RF5 precarga cuentas de PDI, PAS e Investigadores para las pruebas de carga. La
fuente oficial de usuarios es la misma base SQLite que utiliza RF1:
`data/rf1.sqlite3`. No existe ningún JSON de usuarios ni se usa como respaldo.

## Preparación

Desde `PAI2-STX`:

```powershell
python -m pip install -r requirements.txt
python -m src.rf5.cli precargar --total 3
python -m src.rf5.cli resumen
```

Para la prueba completa se puede solicitar hasta 300 usuarios:

```powershell
python -m src.rf5.cli precargar --total 300
```

La operación es idempotente: al repetirla no duplica cuentas ni sustituye
contraseñas. Los roles almacenados son `PDI`, `PAS` e `INVESTIGADOR`, y todas
las cuentas llevan `origin = RF5`. Una cuenta creada manualmente (`origin =
MANUAL`) nunca se modifica; si coincide su nombre con uno que RF5 necesita,
la operación termina con un error de colisión.

Las contraseñas aleatorias temporales se escriben únicamente en
`pki/clients/rf5/credenciales.csv`, para poder ejecutar el benchmark. SQLite
solo conserva el hash `scrypt`; el CSV no debe subirse al repositorio ni
usarse como fuente de autenticación.

## Certificados cliente

La emisión requiere que ya existan `pki/ca/ca.crt` y `pki/ca/ca.key`:

```powershell
python -m src.rf5.cli certificados --limite 3
python -m src.rf5.cli certificados
python -m src.rf5.cli resumen
```

Se genera un par RSA-2048 por cuenta en `pki/clients/rf5/`. Cada emisión
registra o actualiza su fila en `device_pairings`, incluyendo el dispositivo,
la huella de la clave pública, el número de serie y la ruta del certificado.
Repetir el comando reutiliza los pares existentes y no sustituye sus claves.

Guardar claves privadas en el servidor solo es aceptable para el laboratorio y
el simulador de carga. En un BYOD real, la clave debe generarse y permanecer
en el dispositivo.

## Pruebas

```powershell
python -m pytest -q tests/test_rf5.py
```

Las pruebas usan una SQLite temporal e incluyen reparto de 300 cuentas,
hashes compatibles con RF1, idempotencia, preservación de usuarios manuales,
consulta de perfiles, integridad del registro de dispositivos y reutilización
de certificados.
