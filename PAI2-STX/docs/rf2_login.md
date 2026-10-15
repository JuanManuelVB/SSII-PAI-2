# RF2 — Inicio de sesión con autenticación en dos capas (mTLS + credenciales)

## Requisito

> RF2. Permitir el inicio de sesión únicamente si se supera la validación previa
> del certificado digital del dispositivo BYOD (capa de red/transporte) combinada
> con el par usuario/contraseña introducido por el usuario (capa de aplicación).

## Diseño

| Capa | Qué se comprueba | Dónde |
|---|---|---|
| 1. Transporte | Handshake TLS 1.3 con certificado cliente obligatorio, firmado por la CA corporativa y vigente (OpenSSL) | `src/server/tls.py` (`crear_contexto_tls_servidor`, RS1/RS2) |
| 1→2. Identidad | Huella SHA-256 de la clave pública (SubjectPublicKeyInfo DER) del certificado negociado | `src/server/identidad_certificado.py` (`huella_desde_conexion_tls`), que reutiliza `obtener_huella_clave_certificado` de `tls.py` |
| 2. Aplicación | Usuario existente, contraseña scrypt correcta, usuario `active`, huella emparejada **con ese mismo usuario** y dispositivo `active` | `src/server/autenticacion.py` (`autenticar_usuario`) |

La huella se calcula sobre la clave pública y no sobre el certificado completo
porque es el valor que RF1 (`app.py`) y RF5 (`gestion.py`) guardan en
`device_pairings.public_key_fingerprint`.

La huella **nunca** debe aceptarse desde el cuerpo de la petición o una cabecera
HTTP: debe obtenerse de la conexión TLS ya validada.

## Interfaz

```python
from src.server.identidad_certificado import huella_desde_conexion_tls
from src.server.autenticacion import autenticar_usuario, ErrorAutenticacion

huella = huella_desde_conexion_tls(socket_tls)          # capa 1
try:
    resultado = autenticar_usuario(usuario, contrasena, huella)  # capa 2
    # resultado: username, role, origin, device_id, certificate_serial
except ErrorAutenticacion as error:
    # str(error) == "Autenticación rechazada" (mensaje público único)
    # error.motivo -> código interno para la auditoría (RS4)
    ...
```

Orden de comprobaciones y motivo interno de cada rechazo:

| # | Comprobación | Excepción | `motivo` |
|---|---|---|---|
| 1 | Huella SHA-256 hexadecimal de 64 caracteres | `HuellaInvalida` | `invalid_certificate_fingerprint` |
| 2 | El usuario existe | `UsuarioInexistente` | `unknown_user` |
| 3 | La contraseña coincide (scrypt, `verificar_contrasena`) | `ContrasenaIncorrecta` | `invalid_password` |
| 4 | `users.status = 'active'` | `UsuarioInactivo` | `inactive_user` |
| 5 | La huella está en `device_pairings` | `CertificadoNoEmparejado` | `unpaired_certificate` |
| 6 | El emparejamiento pertenece a ese usuario | `CertificadoDeOtroUsuario` | `certificate_user_mismatch` |
| 7 | `device_pairings.status = 'active'` | `DispositivoRevocado` | `revoked_device` |

Nunca se devuelve éxito si falla alguna comprobación. Si la base de datos no
existe se lanza `FileNotFoundError` (error de configuración) y no se crea una
base vacía.

## Decisiones de seguridad

- **Mensaje público único.** Todos los rechazos muestran "Autenticación
  rechazada" para no revelar si el usuario existe o qué capa falló. El motivo
  concreto solo queda en `motivo`, sin contraseña ni datos de la petición.
- **Sin enumeración por tiempo.** Si el usuario no existe se verifica la
  contraseña contra un hash scrypt ficticio. Medición (mediana de 20 intentos,
  Linux, Python 3.10): usuario inexistente 71,1 ms; usuario existente con
  contraseña errónea 69,0 ms.
- **Contraseñas.** Solo se compara con el hash scrypt almacenado; RF2 no
  escribe en la base de datos.
- **Sin duplicar TLS.** El cálculo de la huella es el de `tls.py` (Persona 1).
- **Conexiones SQLite cerradas** explícitamente (`contextlib.closing`).

## Pruebas (`tests/test_login.py`)

| Prueba | Resultado esperado |
|---|---|
| Login correcto, usuario manual | Aceptado |
| Login correcto, usuarios RF5 (PDI, PAS, INVESTIGADOR) | Aceptados |
| Login con huella obtenida de un handshake mTLS TLS 1.3 real | Aceptado; versión `TLSv1.3` |
| Huella en mayúsculas | Normalizada y aceptada |
| Contraseña incorrecta | `ContrasenaIncorrecta` |
| Usuario inexistente | `UsuarioInexistente` |
| Usuario inexistente ejecuta scrypt | Una verificación contra hash ficticio |
| Usuario `blocked` / `revoked` | `UsuarioInactivo` |
| Certificado de la CA no emparejado | `CertificadoNoEmparejado` |
| Certificado emparejado con otro usuario | `CertificadoDeOtroUsuario` |
| Dispositivo revocado | `DispositivoRevocado` |
| Huella con formato inválido (6 casos) | `HuellaInvalida` |
| Todos los rechazos comparten mensaje público | 7 motivos, 1 mensaje |
| Base de datos inexistente | `FileNotFoundError`, no se crea |
| Contraseña nunca en claro | Solo `scrypt$...` en SQLite |

Ejecución (desde `PAI2-STX`):

```powershell
python -m pytest tests/test_login.py -v -s
```

Resultado verificado: `21 passed` en `test_login.py`; batería completa
`56 passed` (Linux, Python 3.10.12). Pendiente de repetir en Windows.

## Fuera del alcance de RF2

- Creación de sesión, expiración y logout: RF4 (Persona 3).
- Registro de eventos de auditoría: RS4 (Persona 3), usando `motivo`.
- Comprobación de la CRL en el handshake: RS1 (Persona 1).
- Endpoint de login en `app.py`: integración final.
