# Recursos para probar RF5

Estas pruebas están diseñadas para ejecutarse desde la carpeta `PAI2-STX` y
no escriben en `data/rf1.sqlite3`. Cada prueba crea una base SQLite temporal.

## Ejecutar todas las pruebas

```powershell
python -m pytest -q tests/test_rf5.py tests/test_rf5_recursos.py
```

## Qué comprueba cada archivo

- `test_rf5.py`: precarga, reparto de 300 cuentas, idempotencia, preservación
  de cuentas manuales, consulta de perfiles y reutilización de certificados.
- `test_rf5_recursos.py`: rechazo de CSV manipulado, ejecución real del CLI y
  propiedades del certificado cliente (`clientAuth`, `CN` y emparejamiento).

## Probar manualmente el flujo completo

```powershell
# 1. Crear tres usuarios RF5 en la SQLite compartida.
python -m src.rf5.cli precargar --total 3

# 2. Ver estadísticas sin mostrar contraseñas.
python -m src.rf5.cli resumen

# 3. Cuando existan pki/ca/ca.crt y pki/ca/ca.key:
python -m src.rf5.cli certificados --limite 3
python -m src.rf5.cli resumen
```

El primer comando crea el CSV local
`pki/clients/rf5/credenciales.csv`. Ese fichero contiene las contraseñas
temporales del laboratorio y no debe compartirse ni subirse a Git. La base de
datos conserva únicamente hashes `scrypt`.

## Pruebas negativas útiles

```powershell
# Debe fallar porque no existe la CA.
python -m src.rf5.cli certificados --limite 1

# Debe fallar porque el total mínimo válido es 3.
python -m src.rf5.cli precargar --total 2
```

Una prueba correcta de emisión debe dejar un `.crt` y un `.key` por usuario en
`pki/clients/rf5/` y una fila relacionada en `device_pairings`.
