#!/usr/bin/env bash
# RS4 (manual): exporta de Access Server los registros de conexión, desconexión
# e intentos de acceso no autorizados, y la versión/cipher TLS del CANAL DE
# CONTROL de la VPN (RS2). No incluye claves ni contraseñas.
#
# Requiere Access Server instalado y en marcha (bash laboratorio.sh instalar).
# Uso: sudo bash scripts/manual/exportar_logs_as.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

SACLI=/usr/local/openvpn_as/scripts/sacli
LOGDBA=/usr/local/openvpn_as/scripts/logdba
LOG_AS=/var/log/openvpnas.log
DESTINO=evidencias/logs
mkdir -p "$DESTINO"

if [[ ! -x "$LOGDBA" ]]; then
  echo "No se encuentra logdba ($LOGDBA). ¿Está instalado Access Server?" >&2
  exit 1
fi

# 1) Todas las sesiones VPN recientes (conexión/desconexión, duración, bytes).
#    Campos acotados: ni tokens ni contraseñas; solo trazabilidad de acceso.
echo "[1/3] Sesiones VPN (último mes)"
sudo "$LOGDBA" --csv --service_filt=VPN \
  --columns="username,start_time,duration,bytes_total,real_ip,error" \
  --start_time_ge="-1M" > "$DESTINO/as_conexiones_vpn.csv"

# 2) Intentos de autenticación fallidos (acceso no autorizado), último mes.
echo "[2/3] Intentos de autenticación fallidos (último mes)"
sudo "$LOGDBA" --csv --start_time_ge="-1M" --auth_bfilt=0 \
  --columns="username,start_time,real_ip,error" > "$DESTINO/as_auth_fallidos.csv"

# 3) Versión y cipher TLS del canal de control OpenVPN (evidencia RS2 del túnel).
echo "[3/3] TLS del canal de control OpenVPN (openvpnas.log)"
if [[ -r "$LOG_AS" ]]; then
  sudo grep -aiE "Control Channel:|TLS version|Data Channel|VERIFY OK|Outgoing|Incoming" "$LOG_AS" \
    | tail -n 50 > "$DESTINO/as_tls_canal_control.txt" || true
else
  echo "  (sin acceso a $LOG_AS; revisa journalctl -u openvpnas)" \
    > "$DESTINO/as_tls_canal_control.txt"
fi

# Ajusta propietario para que el usuario (no root) pueda leer/empaquetar.
sudo chown "${SUDO_USER:-$(id -un)}":"${SUDO_USER:-$(id -gn)}" \
  "$DESTINO/as_conexiones_vpn.csv" "$DESTINO/as_auth_fallidos.csv" \
  "$DESTINO/as_tls_canal_control.txt" 2>/dev/null || true

echo
echo "Generado en $DESTINO/:"
echo "  as_conexiones_vpn.csv     (conexión/desconexión, duración, IP, error)"
echo "  as_auth_fallidos.csv      (intentos de acceso no autorizados)"
echo "  as_tls_canal_control.txt  (TLS 1.3 y cipher del túnel OpenVPN)"
echo "Revisa que NO contengan datos sensibles antes de incluirlos en la entrega."
