#!/usr/bin/env bash
# Paso 3: OpenVPN Access Server (VPN SSL/TLS) + API REST + TLS 1.3 + usuario demo.
# La primera vez instala y configura; las siguientes solo comprueba y arranca.
source "$(dirname "${BASH_SOURCE[0]}")/comun.sh"
exigir_python
preparar_directorios_privados

# Huella oficial de la clave del repositorio de Access Server.
HUELLA_REPO_AS=8B1BC7FECB7259E1430A3AA026EB39123AAAAA96
WEBTLS=/etc/byodsec-local-webtls

. /etc/os-release
case "${VERSION_CODENAME:-}" in
  jammy|noble|resolute) CODENAME="$VERSION_CODENAME" ;;
  *) die "Ubuntu ${VERSION_ID:-?} no está soportado por el repositorio de Access Server" ;;
esac
case "$(dpkg --print-architecture)" in
  amd64|arm64) ARCH="$(dpkg --print-architecture)" ;;
  *) die 'Arquitectura no soportada por Access Server' ;;
esac

# No tomar posesión de un Access Server configurado fuera de este laboratorio.
if [[ ! -f "$MARKER" && ! -f "$OWNER" ]] \
   && dpkg-query -W -f='${Status}' openvpn-as 2>/dev/null | grep -q 'install ok installed'; then
  die 'Ya existe un Access Server no gestionado por BYODSEC. Usa una distribución WSL limpia.'
fi
mantener_sudo

instalar_access_server() {
  printf 'lab-propio=1\n' > "$OWNER"; chmod 600 "$OWNER"

  log 'Paso 3/5 · Repositorio oficial de OpenVPN Access Server'
  local clave
  clave="$(mktemp)"
  curl -fsSL https://packages.openvpn.net/as-repo-public.asc -o "$clave"
  local huellas
  huellas="$(gpg --show-keys --with-colons "$clave" 2>/dev/null || true)"
  grep -q "^fpr:.*:${HUELLA_REPO_AS}:" <<<"$huellas" \
    || die 'La clave descargada del repositorio no tiene la huella oficial esperada'
  # 644: apt verifica las firmas con el usuario _apt, que debe poder leerla.
  sudo install -d -m 755 /etc/apt/keyrings
  sudo install -m 644 "$clave" /etc/apt/keyrings/as-repository.asc
  rm -f "$clave"
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/as-repository.asc] http://packages.openvpn.net/as/debian %s main\n' \
    "$ARCH" "$CODENAME" | sudo tee /etc/apt/sources.list.d/openvpn-as-repo.list >/dev/null
  sudo chmod 644 /etc/apt/sources.list.d/openvpn-as-repo.list
  ok "Clave verificada ($HUELLA_REPO_AS) y repositorio $CODENAME añadido"

  log 'Paso 3/5 · Instalando openvpn-as (puede tardar varios minutos)'
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openvpn-as >/dev/null
  sudo systemctl enable --now openvpnas
  sudo systemctl is-active --quiet openvpnas || die 'Access Server no arrancó; consulta: journalctl -u openvpnas'
  ok 'Servicio openvpnas activo'

  log 'Paso 3/5 · Certificado HTTPS propio para la web/API de Access Server'
  # CA local SOLO para el HTTPS administrativo; no sustituye la CA corporativa de RF1/RF2.
  sudo install -d -m 700 "$WEBTLS"
  sudo tee "$WEBTLS/ca.cnf" >/dev/null <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[dn]
CN = BYODSEC Local Web CA
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  sudo tee "$WEBTLS/server.cnf" >/dev/null <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF
  sudo openssl req -x509 -newkey rsa:3072 -noenc -sha256 -days 1825 -config "$WEBTLS/ca.cnf" \
    -keyout "$WEBTLS/ca.key" -out "$WEBTLS/ca.crt" >/dev/null 2>&1
  sudo openssl req -new -newkey rsa:3072 -noenc -keyout "$WEBTLS/server.key" \
    -out "$WEBTLS/server.csr" -subj /CN=localhost >/dev/null 2>&1
  sudo openssl x509 -req -in "$WEBTLS/server.csr" -CA "$WEBTLS/ca.crt" -CAkey "$WEBTLS/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -out "$WEBTLS/server.crt" -days 365 -sha256 \
    -extfile "$WEBTLS/server.cnf" >/dev/null 2>&1
  sudo openssl verify -x509_strict -purpose sslserver -verify_hostname localhost \
    -CAfile "$WEBTLS/ca.crt" "$WEBTLS/server.crt" >/dev/null
  sudo chmod 600 "$WEBTLS/ca.key" "$WEBTLS/server.key"
  sudo "$SACLI" --key cs.priv_key --value_file "$WEBTLS/server.key" ConfigPut >/dev/null
  sudo "$SACLI" --key cs.cert --value_file "$WEBTLS/server.crt" ConfigPut >/dev/null
  sudo "$SACLI" --key cs.ca_bundle --value_file "$WEBTLS/ca.crt" ConfigPut >/dev/null
  # shellcheck disable=SC2024  # lee como root, escribe como el usuario (propietario de la copia)
  sudo cat "$WEBTLS/ca.crt" > "$LAB/access-server-ca.crt"
  chmod 644 "$LAB/access-server-ca.crt"
  ok 'HTTPS de Access Server con certificado verificable para localhost'

  log 'Paso 3/5 · RS2: TLS 1.3 mínimo en VPN y web, API REST y autenticación local'
  sudo "$SACLI" --key vpn.server.tls_version_min --value 1.3 ConfigPut >/dev/null
  sudo "$SACLI" --key cs.tls_version_min --value 1.3 ConfigPut >/dev/null
  sudo "$SACLI" --key openapi.web_access --value 1 ConfigPut >/dev/null
  sudo "$SACLI" --key auth.module.type --value local ConfigPut >/dev/null

  # Administrador LOCAL con contraseña aleatoria que nunca se muestra.
  local admin_password
  admin_password="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  sudo "$SACLI" --user openvpn --key prop_superuser --value true UserPropPut >/dev/null
  sudo "$SACLI" --user openvpn --key user_auth_type --value local UserPropPut >/dev/null
  sudo "$SACLI" --user openvpn --new_pass "$admin_password" SetLocalPassword >/dev/null
  sudo "$SACLI" start >/dev/null
  ( umask 077
    printf 'BYODSEC_AS_URL=https://localhost:943\nBYODSEC_AS_ADMIN_USER=openvpn\nBYODSEC_AS_ADMIN_PASSWORD=%s\nBYODSEC_AS_CA_BUNDLE=%s\nBYODSEC_VPN_REST=1\nBYODSEC_VPN_DEFAULT_DENY=confirmed\n' \
      "$admin_password" "$LAB/access-server-ca.crt" > "$ENVFILE" )
  unset admin_password
  # El marcador va ANTES de crear usuarios: un reintento no regenera la CA web
  # ni cambia la contraseña de administración.
  printf 'byodsec-lab-version=2\n' > "$MARKER"; chmod 600 "$MARKER"
  ok "Credenciales de administración guardadas solo en $ENVFILE (600)"
}

if [[ -f "$MARKER" ]]; then
  log 'Paso 3/5 · Access Server ya instalado por este laboratorio'
else
  instalar_access_server
fi

cargar_entorno
sudo systemctl start openvpnas
log 'Paso 3/5 · Esperando a la API REST de Access Server'
listo=0
for _ in $(seq 1 30); do
  if "$PY" -m tools.comprobar_access_server >/dev/null 2>&1; then listo=1; break; fi
  sleep 3
done
[[ "$listo" == 1 ]] || die 'La API REST no responde; consulta: journalctl -u openvpnas'
ok 'API REST operativa (HTTPS verificado, sin verify=False)'

log "Paso 3/5 · Cuenta VPN de demostración $USUARIO_DEMO (bloqueada por defecto)"
propiedades="$(sudo "$SACLI" --pfilt "$USUARIO_DEMO" UserPropGet)"
if grep -q "\"$USUARIO_DEMO\"" <<<"$propiedades"; then
  ok 'La cuenta ya existe en Access Server'
else
  "$PY" -m src.vpn_rest_as.provision --usuario "$USUARIO_DEMO" --apply
  # Access Server exige su propia contraseña VPN además de RF2: se usa la
  # contraseña RF5 generada en ESTE equipo (nunca sale del ordenador).
  rf5_password="$("$PY" - "$USUARIO_DEMO" <<'PY'
import csv, sys
with open('pki/clients/rf5/credenciales.csv', newline='', encoding='utf-8') as f:
    filas = [r['password'] for r in csv.DictReader(f) if r['username'] == sys.argv[1]]
assert len(filas) == 1, 'Falta la credencial local del usuario demo'
print(filas[0])
PY
)"
  sudo "$SACLI" --user "$USUARIO_DEMO" --key user_auth_type --value local UserPropPut >/dev/null
  sudo "$SACLI" --user "$USUARIO_DEMO" --new_pass "$rf5_password" SetLocalPassword >/dev/null
  unset rf5_password
  sudo "$SACLI" start >/dev/null
  ok 'Cuenta creada con deny=true y autologin=false'
fi

PERFIL="$LAB/clients/$USUARIO_DEMO.ovpn"
if [[ -s "$PERFIL" ]]; then
  ok "Perfil VPN existente: $PERFIL"
elif "$PY" -m tools.generar_perfil_vpn --usuario "$USUARIO_DEMO" --destino "$PERFIL" >/dev/null; then
  ok "Perfil VPN userlogin generado por REST: $PERFIL"
else
  aviso 'No se pudo generar el perfil .ovpn por REST; el resto del laboratorio sigue funcionando.'
fi
