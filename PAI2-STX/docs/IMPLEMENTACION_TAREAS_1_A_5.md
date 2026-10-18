# BYODSEC — Desarrollo de las tareas 1 a 5

Este documento se refiere al PDF **PAI-2 VPN SSL Road Warrior**, requisitos RF1, RF2, RF4, RF5 y RS1. Se distinguen expresamente las pruebas automatizadas del funcionamiento de un túnel real.

## Qué se ha incorporado

| Tarea | Implementación añadida | Estado comprobable |
|---|---|---|
| 1. Conexión VPN real | Perfiles `userlogin` mediante API REST de Access Server, menú 9 para consultar conexiones reales y API de recurso interno + test antes/durante/después | Código listo; **requiere conectar OpenVPN Connect** y comprobar tráfico real |
| 2. RF4 | REST deny=true, restart warm, disconnect; consulta posterior a `/vpn/status` antes de informar `200`; tokens revocados incluso si REST falla | Tests pasan; **falta prueba contra AS real con un cliente conectado** |
| 3. RF2 + OpenVPN | Permisos AS concedidos exclusivamente con sesión RF2/mTLS; prohibido autologin, solo un dispositivo activo por cuenta; rollback y revocación si falla autorizar; perfil VPN con contraseña | Pruebas pasan. **La contraseña y la PKI internas de Access Server no son todavía la misma identidad criptográfica que la CA corporativa RF1** |
| 4. RF1/RF5 | Disparadores SQLite de inmutabilidad de identidad/clave/serie, revocación permitida; auditoría de cantidad, roles y certificados; emisión existente de 300 certificados | Auditor automático y tests; ejecutar emisor en laboratorio local |
| 5. RS1 | Validador público de CA, firma, vigencia, EKU `clientAuth`, coincidencia CN/OU, número de serie y huella de clave con SQLite; tests mTLS | Validación gateway disponible; **revisar también certificados reales de los perfiles VPN de AS** |

No se han usado sockets de administración OpenVPN. El túnel de datos sigue siendo OpenVPN, y la administración se realiza por **HTTPS REST nativa de Access Server 3.2+**.

## Instalación del parche

1. Copiar los archivos encima de una copia del proyecto, conservando lo que ya exista en `pki/`, `data/` y las configuraciones privadas. No se incluyen secretos en el ZIP.
2. Activar el entorno virtual e instalar dependencias desde `requirements.txt`.
3. Ejecutar pruebas rápidas desde la raíz:

```bash
python -m pytest -q tests/test_tareas_1_5.py tests/test_vpn_rest_as.py tests/test_vpn_rest_integration.py tests/test_interfaz_consola.py
```

4. Si quieren realizar también los tests de PKI y auditar los **300 certificados reales**:

```bash
# Solo la primera vez y con su propia CA de laboratorio, no sobre PKI ajena.
python -m src.rf5.cli certificados --limite 300
bash vpn/scripts/validar_tareas_1_5.sh
```

La auditoría puede fallar si faltan certificados RF5, si están revocados o si hay menos de 300 cuentas: informa de **incumplimiento**, no crea datos inventados. Algunas emisiones pueden requerir tiempo.

## Preparar un perfil real de OpenVPN (en Ubuntu WSL)

Comprobar primero que `BYODSEC_AS_URL`, `BYODSEC_AS_ADMIN_USER`, `BYODSEC_AS_ADMIN_PASSWORD` y `BYODSEC_AS_CA_BUNDLE` se encuentran configuradas, que la CA es correcta y `python -m tools.comprobar_access_server` devuelve REST OK.

La cuenta `rf5_inv_001` debe existir en Access Server y estar inicialmente bloqueada. Usar:

```bash
python -m tools.preparar_perfil_vpn_as rf5_inv_001 --device-id rf5-inv-001-dev01
```

Se crea `pki/clients/rf5/rf5_inv_001.ovpn` con permisos privados. NO compartir este perfil por GitHub. Importarlo en **OpenVPN Connect** de Windows. El perfil requiere credenciales VPN de Access Server; actualmente las contraseñas de la aplicación y de AS no están sincronizadas automáticamente.

Un perfil emitido por AS utiliza normalmente **certificados emitidos por la PKI interna de Access Server**, además del certificado corporativo empleado para el login mTLS del gateway. La vinculación uno-a-uno del certificado VPN concreto con la clave RF1 es una comprobación pendiente de RS1 estricto, no debe afirmarse sin evidencia.

## Servidor integrado en WSL

En una terminal con variables REST configuradas:

```bash
sudo systemctl start openvpnas
export BYODSEC_VPN_REST=1
export BYODSEC_VPN_DEFAULT_DENY=confirmed
python -m src.vpn_rest_as.ejecutar --port 9443
```

En PowerShell de Windows, desde la raíz del proyecto:

```powershell
$env:BYODSEC_VPN_REST = '1'
py -m src.client.interfaz --url https://localhost:9443
```

Entrar con la opción 2 (RF2). **Opción 9: estado VPN real**. Debe decir `Conectado: False` si aún no se ha establecido el túnel. Conectar el perfil en OpenVPN Connect y repetir opción 9: debe mostrar `Conectado: True`, la dirección virtual y el cifrado.

## Probar que un recurso solo puede alcanzarse por el túnel

Para un laboratorio con Access Server, en Ubuntu se puede identificar la IPv4 de una interfaz `as0t*` mediante `ip -br -4 addr` (p.ej. `172.27.224.1`, solo como ejemplo). Servir la API sobre esa IPv4 asignada:

```bash
python -m tools.recurso_interno_vpn --host 172.27.224.1 --port 8080
```

Desde **otro equipo o VM cliente aislada**, sustituir la IP por la real:

```powershell
py -m tools.probar_tunel --fase sin-vpn --ip 172.27.224.1
# Autenticarse por RF2, importar/conectar el perfil userlogin
py -m tools.probar_tunel --fase con-vpn --ip 172.27.224.1
# Ejecutar el logout RF4 de BYODSEC; comprobar que Connect se desconectó
py -m tools.probar_tunel --fase tras-logout --ip 172.27.224.1
```

Cada paso registra un JSON de resultado en `evidencias/logs/acceso_vpn.jsonl`. La herramienta **no fabrica éxitos**; devuelve error si el resultado no es el esperado. No sustituye las capturas de interfaces y rutas ni el análisis de paquetes. Si Windows es anfitrión del mismo WSL, podría existir una ruta alternativa a la interfaz: usar otra VM o equipo y verificar la ruta real para demostrar aislamiento.

Para superar RF4 real: comprobar que, antes de logout, `GET /api/v1/vpn/me` devuelve `count > 0`; después de logout la API REST de AS debe devolver cero conexiones de ese usuario, el perfil debe dejar de funcionar y debe ser imposible reconectarlo sin RF2.

## Qué falta para declarar «completadas» las cinco tareas en el ordenador del alumno

- Importar perfil individual y conectar un túnel real Access Server en Windows u otro cliente.
- Configurar la autenticación de perfil VPN en Access Server y comprobar que no funciona por sí sola cuando la cuenta está bloqueada.
- Verificar el recurso interno inaccesible antes y después, accesible durante, usando rutas reales.
- Registrar capturas del túnel activo, desconexión RF4 y posterior reconexión denegada.
- Comprobar 300 certificados válidos y la PKI concreta usada en el túnel, que no es automáticamente la misma que la CA web o del gateway BYODSEC.

La edición gratuita de Access Server limita las conexiones simultáneas; el benchmark RS3 de 300 túneles queda fuera de estas primeras cinco tareas.

## Precaución con los secretos

`pki/ca/ca.key`, `*.key`, `credenciales.csv`, `*.ovpn`, `.env`, SQLite real y claves de administración nunca deben subirse a Git. Antes de compartir el código, regenerar los secretos que aparecieron en capturas previas.
