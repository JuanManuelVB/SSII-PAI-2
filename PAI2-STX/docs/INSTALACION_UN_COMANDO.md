# BYODSEC: laboratorio independiente de un comando

Este kit se aplica sobre **PAI2-STX integrado**. No instala un servidor remoto: reproduce el laboratorio en **cada ordenador**. Los nombres `rf5_inv_001` y de los 299 usuarios adicionales se conservan en los tres equipos, pero **las contraseñas, claves privadas y CA se generan localmente**. Así no es necesario crear usuarios específicos para cada compañero ni distribuir secretos.

## Requisito previo (una sola vez en Windows)

1. WSL2 y Ubuntu 24.04 o 26.04 funcionando con systemd y `/dev/net/tun`.
2. Repositorio Git clonado/actualizado y este parche incluido. Si no está instalado WSL: abrir PowerShell como administrador, ejecutar `wsl --install -d Ubuntu`, reiniciar si Windows lo indica e iniciar Ubuntu para crear la cuenta local. **La primera instalación de WSL puede requerir reinicio**, así que no es razonable prometer que esa parte se resuelva sin intervención ni en una sola ejecución.
3. Conexión a Internet para `apt` y `pip`; permisos `sudo`. Windows no necesita ser servidor VPN.
4. Importante: usar un **Ubuntu limpio** o creado específicamente para BYODSEC. El script evita tomar posesión de un Access Server anterior no gestionado por él.

## El comando

Desde **PowerShell, situado en la carpeta del proyecto**:

```powershell
wsl bash vpn/scripts/iniciar_laboratorio.sh
```

Alternativamente, dentro de Ubuntu WSL, desde `PAI2-STX`: `bash vpn/scripts/iniciar_laboratorio.sh`.

En el primer uso, tras solicitar la contraseña `sudo` (la de Ubuntu), instala dependencias y OpenVPN Access Server, prepara certificado HTTPS verificado estrictamente, configura una cuenta administrativa local aleatoria, crea **los mismos 300 usernames RF5**, los certificados corporativos de laboratorio y una cuenta VPN bloqueada `rf5_inv_001`. Intenta generar el perfil personal `.ovpn` por **API REST nativa** y levanta FastAPI TLS 1.3/mTLS en `localhost:9443` y el registro RF1 TLS 1.3 en `localhost:8444`. Después abre la interfaz de consola en WSL. No se imprimen secretos. **Puede tardar varios minutos**.

La misma orden se puede volver a ejecutar: no debería eliminar SQLite, sobrescribir la CA corporativa ni resetear el administrador en una instalación completada. El gateway se deja levantado en segundo plano. Access Server se gestiona como servicio `systemd`.

## Qué puede probar un compañero

- En el menú: RF5 resumen, RF2 login `rf5_inv_001`, RF2 consulta, RF4 logout y auditoría.
- Contraseña de la prueba: archivo **local** `pki/clients/rf5/credenciales.csv`, usuario `rf5_inv_001`. No publicar ni subir este CSV.
- HTTPS: `https://localhost:943/admin/` (Access Server) y `https://localhost:9443` (API del gateway **mTLS**, no web pública) y `https://localhost:8444` (registro inicial RF1).
- Perfil VPN generado: `~/.config/byodsec/clients/rf5_inv_001.ovpn`, si el endpoint de Access Server está disponible. Para probar desde Windows debe importarlo con OpenVPN Connect y verificar la ruta/servicio privado. No basta con validar el login HTTPS para probar el túnel.
- El script usa REST para la administración en ejecución de OpenVPN. Durante el **bootstrap local** es necesario usar `sacli` para configurar certificados, cuentas y contraseñas iniciales antes de que exista autenticación REST; esto no cambia el diseño de la aplicación.

## Limitaciones que hay que decirle a la profesora

- El paquete y sus tests se comprueban sobre código y OpenSSL, **pero este entorno de ChatGPT no puede ejecutar WSL2 ni conectar a vuestro Access Server real**. Probadlo primero en un segundo ordenador limpio antes de presentar el instalador como verificado de extremo a extremo.
- OpenVPN Access Server gratuito admite **hasta dos conexiones VPN simultáneas**, no 300. Se precargan 300 cuentas/certificados corporativos, pero la prueba RS3 de 300 túneles reales exige otra infraestructura o licencia. No confundir 300 usuarios en SQLite con 300 túneles activos.
- RF2+mTLS en FastAPI y VPN en Access Server son capas distintas. El perfil de Access Server usa su propia PKI; todavía es necesario verificar la vinculación dispositivo-túnel y desmontaje real RF4, y recoger capturas `.pcap` para RS4 y la prueba opcional (+10%).
- Solo se preaprovisiona `rf5_inv_001` en Access Server para la demostración. El resto de cuentas RF5 existen en SQLite con sus certificados y pueden aprovisionarse en Access Server por REST cuando se necesiten; no permite superar el límite de licencia.
- Para probar en el mismo Windows que aloja WSL, importad el perfil `.ovpn` en el cliente. El servicio interno VPN y las reglas de firewall se han de validar en el equipo real; `localhost:9443` no está pensado para acceso remoto desde otros ordenadores.

## Seguridad y Git

Nunca subir `.venv-wsl`, `*.key`, `*.ovpn`, CSV de contraseñas, certificados con claves incrustadas, `.env`, bases SQLite privadas, ni directorios `$HOME/.config/byodsec` o `/etc/byodsec-local-webtls`. El script deja las claves de Access Server en la **carpeta personal Linux** con permisos de usuario y la clave de CA web bajo `/etc` protegida.

Para incluir el instalador en GitHub, revisar primero `git status` y `git ls-files` para localizar secretos ya indexados (un `.gitignore` nuevo no los elimina del historial). El antiguo error `fatal: Authentication failed` en GitHub es independiente del instalador: habrá que configurar correctamente Git Credential Manager, SSH o token y confirmar permisos de escritura sobre el repositorio.

## Diagnóstico si no arranca

En WSL:

```bash
sudo systemctl status openvpnas --no-pager
cat "$HOME/.local/state/byodsec/gateway.log"
cat "$HOME/.local/state/byodsec/registro.log"
source .venv-wsl/bin/activate
source "$HOME/.config/byodsec/laboratorio.env"
python -m tools.comprobar_access_server
python -m pytest -q tests/test_laboratorio_1comando.py tests/test_vpn_rest_integration.py
```

No publiques la salida de `ConfigQuery` ni de `TestWebCerts`: pueden incluir material privado.

## Prueba adicional del túnel real (una vez importado el perfil)

Consultar `ip -br -4 addr` para elegir una interfaz `as0t*` de Access Server. Crear un recurso REST en su IP, por ejemplo `python -m tools.recurso_interno_vpn --host 172.27.224.1 --port 8080` **solo si esa dirección pertenece a tu interfaz**. Desde Windows ejecutar `./vpn/scripts/probar_conectividad.ps1 -VpnIP <IP_VERIFICADA>` sin y con la conexión. La IP de ejemplo no sirve para todos. Un acceso TCP exitoso por sí solo no prueba el túnel: comprobar tabla de rutas, cliente OpenVPN y captura `.pcap`. Esta prueba requiere la conexión VPN realmente establecida; el instalador prepara pero no puede forzar la instalación del controlador VPN en Windows.
