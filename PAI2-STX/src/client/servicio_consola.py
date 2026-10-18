"""Cliente mTLS real para la interfaz de consola BYODSEC (RF1/RF2/RF4).

No imprime ni almacena contraseñas o tokens en disco. Se comunica con las APIs
existentes; no duplica la autenticación del servidor ni modifica RF1/RF2/RF4.
"""
from __future__ import annotations

import base64
import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from src.rf2.autenticacion import mensaje_a_firmar

RAIZ = Path(__file__).resolve().parents[2]
DIR_CLIENTES = RAIZ / "pki" / "clients"
CA_DEFECTO = RAIZ / "pki" / "ca" / "ca.crt"
EXPRESION_DISPOSITIVO = re.compile(r"^[a-zA-Z0-9_.-]{1,128}$")


class ErrorConsola(RuntimeError):
    """Error explicable al usuario de consola, sin filtrar secretos."""


@dataclass(frozen=True)
class IdentidadLocal:
    usuario: str
    dispositivo: str
    certificado: Path
    clave: Path = field(repr=False)


@dataclass(frozen=True)
class ResultadoCierre:
    respuesta: int
    confirmacion: bool
    rechazo_comprobado: bool | None
    codigo_comprobacion: int | None


def encontrar_identidades(directorio: Path = DIR_CLIENTES) -> list[IdentidadLocal]:
    """Lista pares certificado/clave existentes en el equipo, sin leer las claves."""
    if not directorio.is_dir():
        return []
    resultados: list[IdentidadLocal] = []
    # Dos ubicaciones que ya usan RF1 y RF5, sin recursión ilimitada.
    for carpeta in (directorio, directorio / "rf5"):
        if not carpeta.is_dir():
            continue
        for ruta_crt in sorted(carpeta.glob("*.crt")):
            ruta_key = ruta_crt.with_suffix(".key")
            if not ruta_key.is_file():
                continue
            try:
                cert = x509.load_pem_x509_certificate(ruta_crt.read_bytes())
                us = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
                dev = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if not us or not dev:
                    continue
                resultados.append(IdentidadLocal(us[0].value, dev[0].value, ruta_crt, ruta_key))
            except (OSError, ValueError):
                continue
    return resultados


def contexto_cliente(ca: Path, cert: Path | None = None, key: Path | None = None) -> ssl.SSLContext:
    """TLS 1.3; verifica el hostname y el servidor con la CA corporativa."""
    if not ca.is_file():
        raise ErrorConsola(f"Falta el certificado público de la CA: {ca}")
    if (cert is None) != (key is None):
        raise ErrorConsola("Se requieren certificado y clave juntos")
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.verify_mode = ssl.CERT_REQUIRED
    contexto.check_hostname = True
    contexto.load_verify_locations(cafile=str(ca))
    contexto.minimum_version = ssl.TLSVersion.TLSv1_3
    contexto.maximum_version = ssl.TLSVersion.TLSv1_3
    if cert is not None and key is not None:
        if not cert.is_file() or not key.is_file():
            raise ErrorConsola("No se encuentra el certificado o su clave privada")
        contexto.load_cert_chain(str(cert), str(key))
    return contexto


def descripcion_error_http(respuesta: httpx.Response) -> str:
    """Solo muestra el código y el error público; nunca refleja peticiones."""
    try:
        detalle = respuesta.json().get("detail", "")
        if isinstance(detalle, list):
            detalle = "Solicitud con campos inválidos"
        elif not isinstance(detalle, str):
            detalle = ""
    except (ValueError, AttributeError):
        detalle = ""
    return f"HTTP {respuesta.status_code}" + (f": {detalle}" if detalle else "")


def exigir_correcta(respuesta: httpx.Response, esperado: int = 200) -> None:
    if respuesta.status_code != esperado:
        raise ErrorConsola(descripcion_error_http(respuesta))


class ClienteConsola:
    def __init__(self, *, url: str = "https://localhost:8443", ca: Path = CA_DEFECTO,
                 fabrica: Callable[..., httpx.Client] = httpx.Client):
        if not url.startswith("https://"):
            raise ValueError("La dirección del gateway debe usar HTTPS")
        self.url = url.rstrip("/")
        self.ca = ca
        self._fabrica = fabrica
        self._http: httpx.Client | None = None
        self._identidad: IdentidadLocal | None = None
        self._contexto: ssl.SSLContext | None = None
        self._token: str | None = None
        self._caducidad: str | None = None

    @property
    def conectado(self) -> bool:
        return self._http is not None and self._token is not None

    @property
    def usuario(self) -> str | None:
        return self._identidad.usuario if self.conectado and self._identidad else None

    @property
    def caducidad(self) -> str | None:
        return self._caducidad

    def _cerrar_local(self) -> None:
        cliente = self._http
        self._http = None
        self._identidad = None
        self._contexto = None
        self._token = None
        self._caducidad = None
        if cliente is not None:
            cliente.close()

    def desconectar_local(self) -> None:
        """Descarta el token local y los sockets (no equivale a logout de servidor)."""
        self._cerrar_local()

    def iniciar_sesion(self, identidad: IdentidadLocal, password: str) -> dict:
        if self.conectado:
            raise ErrorConsola("Ya hay sesión activa: ciérrala antes de iniciar otra")
        if not password:
            raise ErrorConsola("Se requiere una contraseña")
        try:
            contexto = contexto_cliente(self.ca, identidad.certificado, identidad.clave)
            clave = serialization.load_pem_private_key(identidad.clave.read_bytes(), password=None)
            certificado_pem = identidad.certificado.read_text(encoding="ascii")
            # Comprobar que archivo .key corresponde realmente al certificado.
            certificado = x509.load_pem_x509_certificate(certificado_pem.encode("ascii"))
            if (certificado.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    != clave.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)):
                raise ErrorConsola("El certificado no corresponde a la clave privada seleccionada")
            cliente = self._fabrica(verify=contexto, base_url=self.url, timeout=12.0)
        except (OSError, ValueError, ssl.SSLError) as exc:
            raise ErrorConsola(f"No se puede cargar la identidad de cliente: {exc}") from exc
        try:
            desafio = cliente.post("/api/v1/sessions/challenge", json={
                "username": identidad.usuario, "device_id": identidad.dispositivo,
            })
            exigir_correcta(desafio)
            nonce = desafio.json()["nonce"]
            mensaje = mensaje_a_firmar(nonce, identidad.usuario, identidad.dispositivo)
            if isinstance(clave, rsa.RSAPrivateKey):
                firma = clave.sign(mensaje, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(clave, ec.EllipticCurvePrivateKey):
                firma = clave.sign(mensaje, ec.ECDSA(hashes.SHA256()))
            else:
                raise ErrorConsola("Tipo de clave privada no admitido")
            respuesta = cliente.post("/api/v1/sessions/login", json={
                "username": identidad.usuario, "device_id": identidad.dispositivo,
                "password": password, "nonce": nonce, "certificate": certificado_pem,
                "signature": base64.b64encode(firma).decode("ascii"),
            })
            exigir_correcta(respuesta)
            datos = respuesta.json()
            token = datos["access_token"]
            if not isinstance(token, str) or not token:
                raise ErrorConsola("El gateway no devolvió una sesión válida")
            # Solo en el despliegue VPN REST: autorización administrativa DESPUÉS
            # de RF2/mTLS, nunca antes. Access Server inicia con deny=true.
            if os.getenv('BYODSEC_VPN_REST') == '1':
                habilitar = cliente.post('/api/v1/vpn/authorize',
                                         headers={'Authorization': f'Bearer {token}'})
                if habilitar.status_code != 200:
                    # El gateway revoca la sesión y trata de revertir en AS.
                    # Intentamos revocación adicional por REST mTLS incluso
                    # si el error es de red o el proveedor está caído.
                    try:
                        cliente.post('/api/v1/sessions/abort',
                                     headers={'Authorization': f'Bearer {token}'}, timeout=5)
                    except httpx.RequestError:
                        pass
                    raise ErrorConsola('RF2 válido, pero la VPN no pudo autorizarse: '
                                       + descripcion_error_http(habilitar))
            self._http = cliente
            self._contexto = contexto
            self._token = token
            self._identidad = identidad
            self._caducidad = str(datos.get("expires_at", ""))
            # Nunca devolver el token en el diccionario mostrado por consola.
            return {"usuario": identidad.usuario, "dispositivo": identidad.dispositivo,
                    "expira": self._caducidad, "codigo": respuesta.status_code}
        except Exception:
            cliente.close()
            raise

    def _autorizar(self) -> dict[str, str]:
        if not self.conectado:
            raise ErrorConsola("No existe una sesión activa. Inicia sesión primero")
        return {"Authorization": f"Bearer {self._token}"}

    def consultar_sesion(self) -> dict:
        headers = self._autorizar()
        assert self._http is not None
        respuesta = self._http.get("/api/v1/sessions/me", headers=headers)
        if respuesta.status_code == 401:
            self._cerrar_local()
            raise ErrorConsola("HTTP 401: la sesión ha caducado o fue revocada")
        exigir_correcta(respuesta)
        datos = respuesta.json()
        return {campo: datos.get(campo) for campo in ("username", "device_id", "role", "expires_at")}

    def consultar_vpn(self) -> dict:
        """Consulta por REST las conexiones VPN del usuario ligado a RF2."""
        headers = self._autorizar()
        assert self._http is not None
        respuesta = self._http.get('/api/v1/vpn/me', headers=headers)
        exigir_correcta(respuesta)
        return respuesta.json()

    def cerrar_sesion(self, *, comprobar_revocacion: bool = True) -> ResultadoCierre:
        headers = self._autorizar()
        assert self._http is not None and self._contexto is not None
        contexto = self._contexto
        # Asegurar primero que el servidor confirma la revocación.
        respuesta = self._http.post("/api/v1/sessions/logout", headers=headers)
        if respuesta.status_code == 401:
            self._cerrar_local()
            raise ErrorConsola("HTTP 401: sesión ya inválida o caducada")
        if respuesta.status_code == 503:
            # Logout revoca el token en SQLite aun cuando el proveedor VPN
            # no confirma la desconexión. El usuario nunca debe interpretar
            # este estado como cierre VPN completado.
            self._cerrar_local()
            raise ErrorConsola("Sesión BYODSEC revocada; desconexión VPN sin confirmar. "
                               "Comprueba la opción 9 o el panel de Access Server")
        exigir_correcta(respuesta)
        if respuesta.json().get("status") != "closed":
            raise ErrorConsola("La respuesta de cierre no confirma revocación")
        # Descartar el bearer local y cerrar el cliente HTTP/TLS.
        self._cerrar_local()
        if not comprobar_revocacion:
            return ResultadoCierre(respuesta.status_code, True, None, None)
        # Prueba real: nuevo socket mTLS con el mismo certificado, token viejo.
        with self._fabrica(verify=contexto, base_url=self.url, timeout=12.0) as comprobador:
            posterior = comprobador.get("/api/v1/sessions/me", headers=headers)
        return ResultadoCierre(respuesta.status_code, True, posterior.status_code == 401,
                               posterior.status_code)


def registrar_dispositivo(
    *, usuario: str, password: str, device_id: str,
    ca: Path = CA_DEFECTO, url_registro: str = "https://localhost:8444",
    directorio: Path = DIR_CLIENTES, fabrica: Callable[..., httpx.Client] = httpx.Client,
) -> IdentidadLocal:
    """Alta RF1 real sobre HTTPS, guardando la nueva clave SOLO en este equipo.

    Registro no implementa un túnel VPN; únicamente emite un certificado BYOD.
    """
    if not url_registro.startswith("https://"):
        raise ErrorConsola("El registro requiere HTTPS")
    if not EXPRESION_DISPOSITIVO.fullmatch(device_id) or device_id.startswith("."):
        raise ErrorConsola("Device ID inválido: solo letras, números, guion, punto o guion bajo")
    if not usuario or len(password) < 12:
        raise ErrorConsola("Se requiere usuario y contraseña corporativa de al menos 12 caracteres")
    ruta_key = directorio / f"{device_id}.key"
    ruta_crt = directorio / f"{device_id}.crt"
    if ruta_key.exists() or ruta_crt.exists():
        raise ErrorConsola("Ya existen archivos para este dispositivo; no se sobrescriben")
    # Generar la clave en el dispositivo, sin enviarla al servidor.
    clave = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    publico = clave.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    contexto = contexto_cliente(ca)
    with fabrica(verify=contexto, base_url=url_registro.rstrip("/"), timeout=20.0) as cliente:
        respuesta = cliente.post("/api/v1/devices/register", json={
            "username": usuario, "password": password, "device_id": device_id,
            "public_key": publico,
        })
    exigir_correcta(respuesta, esperado=201)
    contenido = respuesta.json()
    certificado = x509.load_pem_x509_certificate(contenido["certificate"].encode("ascii"))
    if certificado.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != clave.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ErrorConsola("El servidor devolvió un certificado de clave distinta; NO se guardarán claves")
    directorio.mkdir(parents=True, exist_ok=True)
    privada = clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    # Escritura exclusiva: evita sobrescribir claves existentes por accidente.
    with os.fdopen(os.open(ruta_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(privada)
    try:
        with ruta_crt.open("xb") as f:
            f.write(contenido["certificate"].encode("ascii"))
    except OSError:
        # La cuenta en el servidor YA puede haber quedado registrada.
        raise ErrorConsola(f"Certificado emitido, pero no se pudo guardar {ruta_crt}; conserva {ruta_key}") from None
    return IdentidadLocal(usuario, device_id, ruta_crt, ruta_key)
