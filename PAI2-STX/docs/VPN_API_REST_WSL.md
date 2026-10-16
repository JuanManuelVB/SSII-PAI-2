# BYODSEC — Control REST de OpenVPN en Ubuntu WSL2

Este módulo **no sustituye OpenVPN**: convierte la administración del túnel en operaciones REST internas. Solo el backend de confianza debe invocarlas. No modifica RF1, RF2, RF4 ni RF5.

## 1. Prerrequisitos

- Ubuntu WSL2, OpenVPN 2.7.x con servidor funcionando y `tun0`.
- Python y dependencias `requirements.txt` del proyecto (`fastapi`, `uvicorn`, `httpx`, `pytest`).
- No activar la interfaz de administración de OpenVPN por TCP; utilizar exclusivamente el socket UNIX.
- Ejecutar el servicio REST como usuario normal (no `root`).

## 2. Habilitar la gestión en OpenVPN (Ubuntu)

En WSL2, ejecuta con el usuario normal de Ubuntu:

```bash
sudo groupadd -f byodsec-vpn
sudo usermod -aG byodsec-vpn "$USER"
sudo install -d -o root -g byodsec-vpn -m 0770 /run/byodsec-vpn
```

En `/etc/openvpn/server/byodsec.conf`, añade (solo una vez):

```ini
management /run/byodsec-vpn/management.sock unix
management-client-group byodsec-vpn
```

**No** uses `management 0.0.0.0 ...`, ni autorices a clientes a hablar directamente con el socket. OpenVPN suele crear el socket al iniciarse; los permisos del grupo restringen quién puede utilizarlo. Reinicia el servidor OpenVPN y abre una **nueva sesión WSL** para aplicar el nuevo grupo:

```bash
id -nG
sudo openvpn --config /etc/openvpn/server/byodsec.conf
```

Mientras el servidor se ejecuta, desde otra terminal Ubuntu comprueba:

```bash
ls -l /run/byodsec-vpn/management.sock
```

Debería existir un socket de tipo `s`, accesible por el grupo `byodsec-vpn`. Si el servidor usa systemd, crea la carpeta con `RuntimeDirectory` o `tmpfiles.d`, ya que `/run` desaparece tras reiniciar WSL.

Si conservas `management-client-user root` de una guía anterior, **elimínalo**; impediría al proceso Python sin privilegios acceder al socket. Las líneas anteriores sustituyen la configuración antigua de management; no deben coexistir dos directivas `management`.

## 3. Crear la clave de servicio REST (solo Ubuntu)

```bash
mkdir -p ~/.config/byodsec
python3 -c 'import secrets,pathlib; p=pathlib.Path.home()/".config/byodsec/vpn_api_token"; p.write_text(secrets.token_urlsafe(48)+"\n")'
chmod 700 ~/.config/byodsec
chmod 600 ~/.config/byodsec/vpn_api_token
export BYODSEC_VPN_API_TOKEN_FILE="$HOME/.config/byodsec/vpn_api_token"
```

No añadas el archivo a Git. Este token da permisos de **desconexión administrativa** y solo debe recibirlo el gateway RF4 que opere dentro del equipo de confianza. Para una conexión a través de otra máquina, no expongas el puerto HTTP: configura HTTPS con autenticación entre servicios (mTLS), o utiliza un canal de administración seguro.

## 4. Ejecutar API REST en WSL2

Desde la raíz `PAI2-STX` (donde exista `src/`):

```bash
python3 -m pip install -r requirements.txt
python3 -m src.vpn_api.ejecutar
```

Si Ubuntu usa gestión externa de Python (`externally-managed-environment`), crea antes un entorno virtual:

```bash
sudo apt install -y python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m src.vpn_api.ejecutar
```

Se inicia **únicamente en `127.0.0.1:8765`**. Si Windows no puede alcanzar `localhost:8765` desde WSL2, revisa el modo de red de WSL; no cambies el bind a `0.0.0.0` sin incorporar TLS y restricciones de red.

## 5. Probar la API REST (en Ubuntu, desde otra terminal)

Vuelve a exportar la variable del token en esa terminal:

```bash
export BYODSEC_VPN_API_TOKEN_FILE="$HOME/.config/byodsec/vpn_api_token"
python3 - <<'PY'
import os, pathlib, httpx
secret = pathlib.Path(os.environ['BYODSEC_VPN_API_TOKEN_FILE']).read_text().strip()
headers = {'Authorization': f'Bearer {secret}'}
base = 'http://127.0.0.1:8765'
for route in ('/api/v1/vpn/status', '/api/v1/vpn/connections'):
    response = httpx.get(base+route, headers=headers, timeout=5)
    print(route, response.status_code, response.json())
PY
```

La primera petición debe mostrar `server: available` y el número de clientes. La segunda mostrará identificadores reales `client_id`, certificado `common_name` y dirección virtual.

## 6. Desconectar por REST (solo cliente de laboratorio)

Con el identificador y nombre común obtenidos del paso 5, usa una petición `POST` autorizada:

```python
from src.vpn_api.cliente_rest import VPNRestClient
from pathlib import Path
client = VPNRestClient('http://127.0.0.1:8765', Path.home().joinpath('.config/byodsec/vpn_api_token').read_text().strip())
print(client.disconnect(client_id=7, expected_common_name='rf5_inv_001'))
```

Sustituye `7` y `rf5_inv_001` por **los valores reales**. No ejecutes el ejemplo sin revisarlos; puede desconectar a un usuario.

Confirma en Windows que se desconecta y `ping 10.8.0.1` deja de funcionar por el túnel. El servicio solo devuelve `disconnected` después de confirmar que el `client_id` desapareció de OpenVPN.

## 7. Seguridad e integración futura con RF4

- **No** se acepta `client_id` del navegador como prueba de identidad. RF4 debe deducir la conexión VPN correspondiente a la sesión ya autenticada en SQLite y **comprobar el certificado real** antes de enviar `client_id` / `expected_common_name` al controlador.
- La orden de desconexión afecta a un cliente determinado, no al servidor completo.
- La API se limita a localhost + Bearer secreto, sin Swagger público. No es una API pública de usuario.
- **Pendiente de integrar con RF4**: al hacer logout, el gateway debe revocar SQLite y solicitar la desconexión. Si el controlador VPN falla, debe registrar el error e informar de que el cierre de VPN no está confirmado, nunca responder que el túnel quedó desmontado.
- **Pendiente para completar la seguridad**: activar control de autorización al conectar OpenVPN (`client-connect`, plugin o `management-client-auth`), enlazando con sesiones vigentes. De lo contrario un cliente desconectado **puede reconectarse con el certificado**.
- `client-kill ... HALT` solicita terminar el cliente; no es una revocación permanente de su certificado.
- Si Windows y WSL2 tienen bases de datos distintas, establece un origen único o una API autenticada. No copies periódicamente una SQLite activa entre sistemas.

## 8. Pruebas automatizadas

```bash
python -m pytest -v tests/test_vpn_api.py
```

Estas pruebas usan dobles y un socket UNIX simulado; no desconectan usuarios reales. La prueba con OpenVPN activo debe realizarse manualmente siguiendo los pasos 5 y 6.
