# PAI2-STX · BYODSEC

Acceso remoto *Road Warrior* para la Universidad U-Secure: VPN SSL/TLS
(OpenVPN Access Server) controlada por un gateway propio con autenticación
mutua TLS 1.3 (mTLS), contraseña y desafío firmado, cierre de sesión que
desmonta el túnel y 300 usuarios corporativos (PDI, PAS e Investigadores).

## Lanzar todo con un solo comando

Requisitos: Windows con **WSL2 + Ubuntu 24.04 o 26.04** (o Ubuntu nativo),
conexión a Internet y la contraseña de `sudo` de Ubuntu.

Desde **PowerShell**, en esta carpeta:

```powershell
wsl bash laboratorio.sh
```

o, dentro de Ubuntu, `bash laboratorio.sh`. Sin argumentos el script:

1. Comprueba el sistema e instala dependencias (entorno Python en `~/.local/share/byodsec`).
2. Crea la PKI corporativa y los **300 usuarios RF5** con su certificado.
3. Instala y configura **OpenVPN Access Server** (HTTPS verificado, TLS 1.3, API REST) y un usuario VPN de prueba bloqueado por defecto.
4. Arranca el **gateway mTLS** (`https://localhost:9443`), el **registro RF1** (`https://localhost:8444`) y el reconciliador RF4.
5. Ejecuta **todas las pruebas** y guarda las evidencias en `evidencias/` (resumen en `evidencias/logs/resumen_pruebas.txt`).
6. Abre el menú del cliente BYODSEC.

Es idempotente: se puede volver a lanzar sin perder la CA, las cuentas ni las
claves. La primera vez tarda varios minutos. Si WSL no tiene systemd activado,
el script lo activa y pide ejecutar `wsl --shutdown` antes de relanzarlo.
Mantén la ventana abierta mientras uses el laboratorio.

Otras órdenes: `bash laboratorio.sh instalar | arrancar | probar | menu | estado | parar | entregar`
y la opción `--sin-vpn` (todo salvo Access Server, útil para diagnóstico).

## Qué prueba `laboratorio.sh probar`

| Prueba | Evidencia |
|---|---|
| 87 pruebas automáticas (pytest) aisladas | `evidencias/logs/pytest.txt`, `pytest_junit.xml` |
| Auditoría de 300 usuarios, roles y certificados | `evidencias/logs/auditoria_rf1_rf5_pki.json` |
| Ataques TLS controlados (extra +10 %) | `evidencias/ataques/tls_opcional.json` |
| Solo TLS 1.3 en los servicios reales (versión y *cipher suite*) | `evidencias/logs/tls_servicios.json` |
| Extremo a extremo real RF1 → RF2 → VPN → RF4 | `evidencias/logs/e2e_laboratorio.json` |
| API REST de Access Server | salida de consola |

La relación completa requisito → código → prueba → evidencia está en
[`docs/trazabilidad.md`](docs/trazabilidad.md), junto con las pruebas
manuales que necesitan el túnel conectado con OpenVPN Connect.

## Estructura

```text
laboratorio.sh          único punto de entrada
scripts/                pasos del laboratorio (1_… a 5_…), estado, parar, entregar
scripts/manual/         capturas .pcap (RS4) y medidas iperf3 (RS3)
src/server/             RF1: registro y emparejamiento de dispositivos
src/rf2/  src/rf4/      RF2: login mTLS + contraseña + desafío · RF4: cierre
src/rf5/                RF5: 300 usuarios y certificados
src/vpn_rest_as/        integración REST con OpenVPN Access Server
src/gateway/            gateway único TLS 1.3/mTLS y servidor de registro
src/client/             cliente y menú de consola
src/common/             SQLite, hash scrypt y rutas TLS comunes
pki/scripts/pki.py      CA corporativa, emisión, revocación y CRL
tools/                  auditoría, comprobación TLS, E2E, perfiles VPN, ataques
tests/                  pruebas automáticas (pytest)
docs/                   trazabilidad e informe
evidencias/  bench/     resultados generados por las pruebas
```

## Usar el laboratorio a mano

- Menú: `bash laboratorio.sh menu` (o desde Windows `py -m src.client.interfaz`).
- Usuario de prueba: `rf5_inv_001`; su contraseña está **solo en local**, en `pki/clients/rf5/credenciales.csv`.
- Perfil VPN: `~/.config/byodsec/clients/rf5_inv_001.ovpn` (`bash laboratorio.sh estado` muestra la ruta de Windows), para importarlo en OpenVPN Connect.
- Panel de Access Server: `https://localhost:943/admin/` (usuario `openvpn`; contraseña en `~/.config/byodsec/laboratorio.env`).

## Seguridad y limitaciones

- No se entregan claves, contraseñas, bases de datos ni perfiles: cada equipo genera los suyos. `bash laboratorio.sh entregar` crea `../PAI2-STX.zip` y comprueba que no contiene secretos.
- Access Server gratuito admite **2 conexiones VPN simultáneas**: hay 300 cuentas con certificado, pero la prueba RS3 de 300 túneles exige licencia u otra infraestructura.
- La PKI del gateway (mTLS) y la PKI interna de Access Server (túnel) son distintas. La vinculación es por identidad: la cuenta VPN solo se habilita tras un login RF2 válido de ese mismo usuario.
