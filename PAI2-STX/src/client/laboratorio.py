"""Acciones de laboratorio para el cliente interactivo BYODSEC (camino A).

No agrega endpoints administrativos públicos. El alta de usuarios y las utilidades
locales se ejecutan mediante WSL en el mismo ordenador que alberga el servidor.
Las capturas se realizan preferentemente en el servidor WSL2 (tcpdump).
También admite TShark/Npcap en Windows como alternativa.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from src.client.servicio_consola import RAIZ, ErrorConsola

_NOMBRE_USUARIO = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,63}$")


def _wsl_exe() -> str:
    if os.name != "nt":
        raise ErrorConsola("Esta operación administrativa está diseñada para el cliente en Windows con WSL2")
    programa = shutil.which("wsl.exe")
    if not programa:
        raise ErrorConsola("No se encontró wsl.exe. Comprueba que Ubuntu WSL2 está instalado")
    return programa


def ejecutar_en_wsl(modulo: str, argumentos: Iterable[str] = (), *, interactivo: bool = False,
                   tiempo_maximo: int = 150) -> subprocess.CompletedProcess[str]:
    """Ejecuta herramientas locales existentes en WSL, sin crear API de alta remota.

    Las rutas se toman del directorio real de PAI2-STX, no de texto introducido
    por usuarios. La ruta de Windows se entrega como argumento a `wslpath`.
    """
    wsl = _wsl_exe()
    if not re.fullmatch(r"[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)+", modulo):
        raise ErrorConsola("Módulo administrativo no permitido")
    # Convertir la ruta con wslpath, sin interpolación de valores aportados por el usuario.
    try:
        conversion = subprocess.run([wsl, "--exec", "wslpath", "-a", str(RAIZ)],
                                    capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=20, check=True)
    except (OSError, subprocess.SubprocessError) as e:
        raise ErrorConsola("No se pudo convertir la ruta de PAI2-STX en WSL; comprueba WSL2") from e
    linux_root = conversion.stdout.strip()
    if not linux_root.startswith("/"):
        raise ErrorConsola("No se pudo resolver la carpeta PAI2-STX dentro de Ubuntu WSL")

    # El módulo y sus argumentos se reciben como argv separados en Python/WSL.
    # bash ejecuta un script fijo; no interpola contraseñas ni argumentos en el shell.
    script = ('cd "$1" || exit 3; shift; '
              'if [ -x .venv-wsl/bin/python ]; then PY=.venv-wsl/bin/python; '
              'elif command -v python3 >/dev/null 2>&1; then PY=python3; '
              'else echo "Falta Python en WSL" >&2; exit 3; fi; '
              'exec "$PY" "$@"')
    orden = [wsl, "--exec", "bash", "-c", script, "byodsec", linux_root,
             "-m", modulo, *[str(v) for v in argumentos]]
    try:
        if interactivo:
            # La contraseña del nuevo usuario se pide directamente en WSL (getpass).
            return subprocess.run(orden, check=False, timeout=tiempo_maximo)
        return subprocess.run(orden, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", check=False, timeout=tiempo_maximo)
    except subprocess.TimeoutExpired as exc:
        raise ErrorConsola("Tiempo de espera agotado al ejecutar la herramienta de WSL") from exc
    except OSError as exc:
        raise ErrorConsola("No se pudo ejecutar el comando de administración en WSL") from exc


def crear_usuario_corporativo(usuario: str, rol: str) -> bool:
    """Alta de cuenta solo para el administrador LOCAL del entorno de laboratorio."""
    if not _NOMBRE_USUARIO.fullmatch(usuario):
        raise ErrorConsola("Usuario: 3-64 caracteres; debe empezar por letra; permite números . _ -")
    if rol not in {"PDI", "PAS", "INVESTIGADOR"}:
        raise ErrorConsola("Rol inválido")
    proceso = ejecutar_en_wsl("src.server.usuarios", ["crear", usuario, rol], interactivo=True)
    return proceso.returncode == 0


def buscar_tshark() -> Path | None:
    posible = shutil.which("tshark.exe") or shutil.which("tshark")
    if posible:
        return Path(posible)
    if os.name == "nt":
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            directorio = os.environ.get(variable)
            if directorio:
                p = Path(directorio) / "Wireshark" / "tshark.exe"
                if p.is_file():
                    return p
    return None


def buscar_wireshark(tshark: Path | None = None) -> Path | None:
    p = shutil.which("Wireshark.exe") or shutil.which("wireshark")
    if p:
        return Path(p)
    if tshark:
        gui = tshark.with_name("Wireshark.exe")
        if gui.exists():
            return gui
    return None


def interfaces_captura(tshark: Path) -> list[tuple[str, str]]:
    try:
        resultado = subprocess.run([str(tshark), "-D"], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ErrorConsola("No se pudieron enumerar interfaces de captura TShark/Npcap") from e
    if resultado.returncode:
        raise ErrorConsola("TShark no puede enumerar interfaces. Comprueba Npcap y sus permisos")
    lista: list[tuple[str, str]] = []
    for linea in resultado.stdout.splitlines():
        coincidencia = re.match(r"^\s*(\d+)\.\s*(.*?)\s*$", linea)
        if coincidencia:
            lista.append((coincidencia.group(1), coincidencia.group(2)))
    return lista


class CapturaTLS:
    def __init__(self):
        self._proceso: subprocess.Popen | None = None
        self._ruta: Path | None = None
        self._tshark: Path | None = None
        self._stderr = None

    @property
    def activa(self) -> bool:
        return self._proceso is not None and self._proceso.poll() is None

    def interfaces(self) -> list[tuple[str, str]]:
        tshark = buscar_tshark()
        if not tshark:
            raise ErrorConsola("Wireshark/TShark no está instalado. Instala Wireshark con Npcap y TShark habilitados")
        return interfaces_captura(tshark)

    def iniciar(self, indice: str, puerto: int = 9443) -> Path:
        if self.activa:
            raise ErrorConsola("Ya hay una captura en marcha. Detenla primero")
        tshark = buscar_tshark()
        if not tshark:
            raise ErrorConsola("Instala Wireshark (incluyendo TShark y Npcap) antes de capturar")
        disponibles = {i for i, _ in interfaces_captura(tshark)}
        if indice not in disponibles:
            raise ErrorConsola("Interfaz de captura no disponible")
        carpeta = RAIZ / "evidencias" / "pcap"
        carpeta.mkdir(parents=True, exist_ok=True)
        nombre = datetime.now(timezone.utc).strftime("byodsec_mtls_%Y%m%d_%H%M%S_%f.pcapng")
        destino = carpeta / nombre
        # TShark guarda pcapng de paquetes TLS reales. No usa SSLKEYLOGFILE.
        log = carpeta / (nombre + ".captura.log")
        self._stderr = log.open("wb")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        try:
            proc = subprocess.Popen([str(tshark), "-i", indice, "-f", f"tcp port {puerto}",
                                     "-w", str(destino), "-q"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=self._stderr,
                                    creationflags=flags)
        except OSError as exc:
            self._stderr.close()
            self._stderr = None
            raise ErrorConsola("No se pudo arrancar TShark; revisa Npcap/permisos") from exc
        self._proceso, self._ruta, self._tshark = proc, destino, tshark
        try:
            proc.wait(timeout=0.8)
            raise ErrorConsola("TShark terminó inmediatamente; revisa el archivo .captura.log")
        except subprocess.TimeoutExpired:
            return destino

    def detener(self) -> tuple[Path, int]:
        if not self._proceso or not self._ruta or not self._tshark:
            raise ErrorConsola("No hay una captura iniciada desde este cliente")
        proc, ruta, tshark = self._proceso, self._ruta, self._tshark
        try:
            if proc.poll() is None:
                if os.name == "nt":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=5)
        finally:
            if self._stderr:
                self._stderr.close()
                self._stderr = None
            self._proceso = None
        if not ruta.is_file() or ruta.stat().st_size == 0:
            raise ErrorConsola("No se ha guardado ningún archivo de captura; comprueba Npcap")
        try:
            ver = subprocess.run([str(tshark), "-r", str(ruta), "-Y", "tcp.port==9443",
                                  "-T", "fields", "-e", "frame.number"], capture_output=True,
                                 text=True, timeout=30)
            cantidad = len([x for x in ver.stdout.splitlines() if x.strip()]) if ver.returncode == 0 else 0
        except (OSError, subprocess.TimeoutExpired):
            cantidad = 0
        return ruta, cantidad

    def abrir_wireshark(self, ruta: Path) -> None:
        gui = buscar_wireshark(self._tshark or buscar_tshark())
        if not gui:
            raise ErrorConsola(f"No se encuentra Wireshark.exe. Abre el archivo manualmente: {ruta}")
        subprocess.Popen([str(gui), str(ruta)], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def cerrar(self) -> None:
        if self._proceso is not None:
            try:
                self.detener()
            except (OSError, ErrorConsola, subprocess.SubprocessError):
                pass


class CapturaTLSServidor(CapturaTLS):
    """Captura TCP 9443 en el Linux que realmente sirve HTTPS (WSL2).

    Evita seleccionar un adaptador Windows que no transporte localhost->WSL.
    Se ejecuta tcpdump en WSL como root; no depende de pedir la clave sudo
    ni de publicar endpoints de administración en FastAPI. Es solo laboratorio.
    """

    def __init__(self):
        super().__init__()
        self._wsl_pid: Path | None = None
        self._wsl_linux_path: str | None = None
        self._wsl_bin: str | None = None
        self._modo_wsl = False

    def interfaces(self) -> list[tuple[str, str]]:
        # WSL se ofrece siempre en Windows. La disponibilidad se comprueba al
        # arrancar y cualquier problema se muestra como un error visible.
        dispositivos = [("WSL", "Ubuntu WSL2: capturar en el servidor (RECOMENDADO)")]
        try:
            dispositivos.extend(super().interfaces())
        except ErrorConsola:
            pass  # TShark/Npcap es opcional si podemos capturar con tcpdump.
        return dispositivos

    def iniciar(self, indice: str, puerto: int = 9443) -> Path:
        if indice != "WSL":
            self._modo_wsl = False
            return super().iniciar(indice, puerto)
        if self.activa:
            raise ErrorConsola("Ya existe una captura activa; deténla antes")
        wsl = _wsl_exe()
        try:
            prueba = subprocess.run(
                [wsl, "-u", "root", "--", "sh", "-c", "command -v tcpdump"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ErrorConsola("No se puede acceder a Ubuntu WSL2 para capturar") from exc
        if prueba.returncode != 0:
            raise ErrorConsola("Falta tcpdump en Ubuntu WSL2. Abre WSL y ejecuta: sudo apt install tcpdump")

        carpeta = RAIZ / "evidencias" / "pcap"
        carpeta.mkdir(parents=True, exist_ok=True)
        nombre = datetime.now(timezone.utc).strftime("byodsec_servidor_%Y%m%d_%H%M%S_%f.pcap")
        destino = carpeta / nombre
        pid_windows = carpeta / (nombre + ".pid")
        log = carpeta / (nombre + ".captura.log")
        try:
            convertir = subprocess.run(
                [wsl, "--exec", "wslpath", "-a", str(destino)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=20, check=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ErrorConsola("No se pudo convertir la ruta del proyecto para WSL2") from exc
        ruta_linux = convertir.stdout.strip()
        if not ruta_linux.startswith("/"):
            raise ErrorConsola("Ruta del archivo de captura no válida dentro de Ubuntu WSL")

        # El PID se guarda junto al PCAP, que Windows y WSL comparten en /mnt/c.
        # El shell se sustituye por tcpdump (exec) para poder pararlo con SIGINT.
        self._stderr = log.open("wb")
        codigo = 'printf "%s\n" "$$" > "$1"; exec tcpdump -Z root -i lo -nn -s 0 -U -w "$2" "tcp port 9443"'
        cmd = [wsl, "-u", "root", "--", "sh", "-c", codigo, "byodsec", ruta_linux + ".pid", ruta_linux]
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=self._stderr,
                                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
        except OSError as exc:
            self._stderr.close()
            self._stderr = None
            raise ErrorConsola("No se pudo iniciar tcpdump en Ubuntu WSL") from exc

        # Esperar hasta que realmente esté escuchando; el inicio de WSL tarda.
        for _ in range(60):
            if proc.poll() is not None:
                break
            if pid_windows.exists() and destino.exists():
                self._proceso, self._ruta = proc, destino
                self._wsl_pid, self._wsl_linux_path, self._wsl_bin = pid_windows, ruta_linux, wsl
                self._modo_wsl = True
                return destino
            time.sleep(0.1)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self._stderr.close()
        self._stderr = None
        raise ErrorConsola(
            f"No se inició tcpdump en WSL; consulta el error: {log}")

    def detener(self) -> tuple[Path, int]:
        if not self._modo_wsl:
            return super().detener()
        proc, ruta, pid_file, wsl = self._proceso, self._ruta, self._wsl_pid, self._wsl_bin
        if proc is None or ruta is None or pid_file is None or wsl is None:
            raise ErrorConsola("No hay captura activa en el servidor")
        try:
            if proc.poll() is None and pid_file.exists():
                pid = pid_file.read_text(encoding="ascii").strip()
                if pid.isdigit():
                    subprocess.run([wsl, "-u", "root", "--", "kill", "-INT", pid],
                                   capture_output=True, timeout=15)
            try:
                proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        finally:
            if self._stderr is not None:
                self._stderr.close()
                self._stderr = None
            self._proceso = None
            self._modo_wsl = False
            try:
                pid_file.unlink(missing_ok=True)
            except OSError:
                pass
        if not ruta.is_file() or ruta.stat().st_size <= 24:
            raise ErrorConsola("La captura de WSL no contiene paquetes; comprueba que el cliente inició sesión durante la captura")

        # Contamos los paquetes reales de TCP 9443. TShark, cuando esté
        # instalado, funciona con capturas obtenidas desde WSL y ofrece el filtro.
        tshark = buscar_tshark()
        if tshark:
            try:
                r = subprocess.run([str(tshark), "-r", str(ruta), "-Y", "tcp.port==9443",
                                    "-T", "fields", "-e", "frame.number"],
                                   capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    return ruta, sum(bool(x.strip()) for x in r.stdout.splitlines())
            except (OSError, subprocess.TimeoutExpired):
                pass
        # Sin TShark, tcpdump imprime una línea por paquete.
        try:
            r = subprocess.run([wsl, "-u", "root", "--", "tcpdump", "-nn", "-r", self._wsl_linux_path],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
            if r.returncode == 0:
                return ruta, sum(bool(x.strip()) for x in r.stdout.splitlines())
        except (OSError, subprocess.TimeoutExpired):
            pass
        return ruta, 0

    def cerrar(self) -> None:
        if self._proceso is not None and self._modo_wsl:
            try:
                self.detener()
            except (OSError, ErrorConsola, subprocess.SubprocessError):
                pass
        else:
            super().cerrar()
