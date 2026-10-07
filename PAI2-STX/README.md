# PAI2-STX

Proyecto de gateway VPN con autenticación mutua TLS (mTLS), acceso BYOD,
auditoría y control de sesiones para los perfiles PDI, PAS e Investigadores.

## Estructura

- `pki/`: autoridad certificadora, certificados y scripts de gestión PKI.
- `src/`: gateway, cliente BYOD y utilidades comunes.
- `config/`: parámetros TLS, rutas, puertos y perfiles de acceso.
- `data/usuarios_precargados/`: cuentas iniciales requeridas por RF5.
- `tests/`: pruebas funcionales, de seguridad y casos negativos.
- `bench/`: generación de carga y resultados de comparación TLS/sin cifrar.
- `evidencias/`: capturas, logs y evidencias de ataques opcionales.
- `docs/`: documentación del informe y matriz de trazabilidad.

## Despliegue rápido

1. Crear la CA corporativa y los certificados de servidor y cliente desde
   `pki/scripts/`.
2. Revisar los parámetros de `config/`, especialmente puertos, rutas PKI,
   versión TLS y perfiles de acceso.
3. Cargar las cuentas iniciales en `data/usuarios_precargados/`.
4. Iniciar el gateway desde `src/server/`.
5. Registrar e iniciar el cliente BYOD desde `src/client/`.
6. Ejecutar las pruebas de `tests/` y guardar logs, capturas y resultados en
   `evidencias/` y `bench/resultados/`.

No se deben incluir claves privadas reales, credenciales ni capturas con datos
 sensibles en el repositorio.
