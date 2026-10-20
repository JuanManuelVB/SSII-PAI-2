# BYODSEC · Camino A (TLS 1.3, mTLS y API REST)

Proyecto de acceso corporativo seguro en **Windows + Ubuntu WSL2**. Esta edición es la limpia del **camino A aprobado por el profesor**: HTTPS/REST protegido mediante TLS 1.3 y autenticación mutua X.509 (mTLS). No implementa un túnel IP VPN; se ha retirado la integración no necesaria con OpenVPN Access Server.

## Funciones que se conservan

- Alta administrativa **local** de usuarios PDI, PAS e Investigadores desde el cliente Windows (operación en WSL; NO existe endpoint público para crear cuentas).
- CA corporativa, emparejamiento RF1 y certificados por dispositivo; precarga RF5 de 300 usuarios.
- Inicio de sesión RF2 con certificado mTLS, desafío firmado y contraseña; sesión con token solo almacenado como hash en SQLite.
- Acceso al recurso interno y envío de mensaje por HTTPS TLS 1.3; servidor confirma SHA-256.
- Logout RF4 y comprobación de rechazo de token revocado HTTP 401.
- Verificación TLS 1.3, auditoría, simulaciones de intentos no autorizados, capturas tcpdump/Wireshark.
- Prueba RS3 de 300 identidades y sesiones activas con mensajes durante un periodo común; incluye control de concurrencia de logins, reintentos auditados y JSON de resultados. No equivale a 300 ordenadores físicos ni 300 túneles VPN.

## Si ya tenías el proyecto funcionando

**NO elimines tu carpeta de trabajo original.** Este ZIP es **código limpio sin secretos**: no incluye `data/rf1.sqlite3`, `pki/ca/ca.key`, `pki/server/server.key`, claves de clientes ni `credenciales.csv`. Esos archivos deben quedarse en tu PC. Haz una copia privada y luego actualiza el código conservando esos archivos. Si montas una carpeta nueva, copia allí *localmente*, sin subirlos a terceros, los datos/PKI anteriores y comprueba las rutas y certificados.

Esta versión recompone los parches de las conversaciones anteriores a partir del **último ZIP completo aportado**, no de posibles ediciones más recientes realizadas solo en tu equipo. Antes de sobrescribir archivos locales nuevos, compáralos.

## Primera instalación limpia (WSL)

Desde Ubuntu WSL en la raíz del proyecto:

```bash
bash laboratorio.sh preparar
bash laboratorio.sh servidor
```

`preparar` crea el entorno virtual, instala dependencias, genera CA/certificados solo si faltan, y precarga 300 usuarios de laboratorio con contraseñas guardadas exclusivamente en `pki/clients/rf5/credenciales.csv`. Si existe una base SQLite sin su CA correspondiente se detiene para evitar romper identidades. **No regeneres una CA si ya registraste dispositivos antes.**

En Windows, arranca con doble clic:

1. `INICIAR_SERVIDOR_BYODSEC.cmd` (dos servicios WSL: HTTPS/mTLS `127.0.0.1:9443` y registro TLS `127.0.0.1:8444`).
2. `INICIAR_CLIENTE_BYODSEC.cmd` (menú simplificado, opciones 1–11).

No inicies dos copias de servidor a la vez: los puertos 9443 y 8444 solo permiten una instancia.

## Pruebas y evidencias

Consulta **[docs/GUIA_DEMOSTRACIONES.md](docs/GUIA_DEMOSTRACIONES.md)**. Para la prueba 300 desde el cliente: `10 (Pruebas y Wireshark) -> 10 (Mantener sesiones)`; los resultados se guardan en `bench/resultados/sesiones_300.json`. Puedes ejecutar también:

```bash
bash laboratorio.sh auditar
bash laboratorio.sh prueba300
python -m tools.comprobar_tls --sin-access-server --json evidencias/logs/tls.json
```

Captura fiable de la prueba ejecutada *dentro de WSL2* (no aparecerá automáticamente en las interfaces de Windows):

```bash
mkdir -p "$HOME/byodsec_capturas"
CAP="$HOME/byodsec_capturas/byodsec_$(date +%Y%m%d_%H%M%S).pcap"
sudo tcpdump -Z "$USER" -i lo -nn -s 0 -U -w "$CAP" 'tcp port 9443'
```

Deja `tcpdump` ejecutándose, inicia la prueba, detenlo con Ctrl+C, y abre el archivo resultante con Wireshark desde `\\wsl$\Ubuntu\home\TU_USUARIO\byodsec_capturas\`. El filtro de visualización es `tcp.port == 9443`.

## Seguridad y empaquetado

El ZIP entregado excluye **bases reales, claves privadas, credenciales y capturas con datos sensibles**. Los archivos de estado se generan y conservan localmente. Si necesitas empaquetar otra versión de código sin secretos: `bash scripts/empaquetar_entrega.sh ../PAI2-STX_CAMINO_A_LIMPIO.zip`.

Para el informe: el profesor autorizó el camino A. Se demuestra una pasarela REST cifrada, *no* el desmontaje de un túnel OpenVPN; RF4 revoca el token y cierra el cliente HTTPS.
