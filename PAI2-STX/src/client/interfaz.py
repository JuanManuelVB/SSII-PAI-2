"""Interfaz de consola interactiva BYODSEC.

Ejecutar desde PAI2-STX:  python -m src.client.interfaz
(o bien: bash laboratorio.sh menu, que arranca antes los servidores).
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from collections import deque
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.markup import escape
    from rich import box
except ImportError as exc:
    raise SystemExit("Falta 'rich'. Instala: python -m pip install -r requirements.txt") from exc

from src.client.servicio_consola import (
    CA_DEFECTO,
    RAIZ,
    ClienteConsola,
    ErrorConsola,
    IdentidadLocal,
    encontrar_identidades,
    registrar_dispositivo,
)
from src.client.laboratorio import CapturaTLSServidor, crear_usuario_corporativo, ejecutar_en_wsl

consola = Console()
RUTA_LOG_RF4 = RAIZ / "evidencias" / "logs" / "rf4-audit.jsonl"
RUTA_LOG_RF1 = RAIZ / "evidencias" / "logs" / "rf1-audit.jsonl"


def cabecera(cliente: ClienteConsola) -> None:
    """Menú ordenado según el recorrido del usuario, sin códigos de requisitos."""
    consola.clear()
    consola.print(Panel.fit(
        "[bold bright_cyan]BYODSEC[/]  [white]· Universidad U-Secure[/]\n"
        "[dim]Acceso corporativo seguro · HTTPS · TLS 1.3 · mTLS[/]",
        border_style="bright_cyan", padding=(1, 3)))
    if cliente.conectado:
        consola.print(f"[green]● SESIÓN ACTIVA[/]  Usuario: "
                      f"[bold]{escape(str(cliente.usuario))}[/]  "
                      f"Caduca: {escape(str(cliente.caducidad or '-'))}")
    else:
        consola.print("[yellow]● SIN SESIÓN[/]  "
                      f"[dim]Servidor: {escape(cliente.url)}[/]")

    secciones = [
        ("USUARIOS Y CERTIFICADOS", [
            ("1", "Crear usuario", "Alta de una cuenta y asignación de rol"),
            ("2", "Generar certificado", "Nuevo dispositivo de un usuario existente"),
            ("3", "Consultar usuarios", "Cuentas corporativas y perfiles"),
            ("4", "Ver certificados", "Certificados disponibles en el equipo"),
        ]),
        ("CONEXIÓN SEGURA", [
            ("5", "Iniciar sesión", "Certificado y contraseña corporativa"),
            ("6", "Consultar mi sesión", "Identidad, dispositivo y permisos"),
            ("7", "Estado de la VPN" if os.getenv("BYODSEC_VPN_REST") == "1"
             else "Acceder y enviar mensaje", "Estado de OpenVPN" if os.getenv("BYODSEC_VPN_REST") == "1"
             else "Recurso protegido y mensaje cifrado"),
            ("8", "Cerrar sesión", "Revocar acceso y comprobar el rechazo"),
        ]),
        ("PRUEBAS Y EVIDENCIAS", [
            ("9", "Demostración completa", "Iniciar sesión, comunicar y cerrar"),
            ("10", "Pruebas y Wireshark", "Capturas, TLS y comprobaciones"),
            ("11", "Auditoría", "Consultar los últimos eventos"),
        ]),
    ]
    for titulo, opciones in secciones:
        consola.print(f"\n[bold cyan]{titulo}[/]")
        tabla = Table(box=None, show_header=False, padding=(0, 2), show_edge=False)
        tabla.add_column("Nº", width=5, no_wrap=True)
        tabla.add_column("Opción", style="bold white", min_width=27)
        tabla.add_column("Descripción", style="dim")
        for num, nombre, descripcion in opciones:
            tabla.add_row(f"[bold bright_cyan][{num}][/]", nombre, descripcion)
        consola.print(tabla)
    consola.print("\n[dim][0] Salir[/]")


def pausa() -> None:
    consola.input("\n[dim]Pulsa Enter para volver al menú...[/]")


def error_publico(exc: Exception) -> None:
    """No imprime trazas con credenciales, tokens ni cuerpos de petición."""
    import httpx
    if isinstance(exc, httpx.ConnectError):
        mensaje = "No se puede conectar. ¿Has arrancado el servidor y generado certificados válidos?"
    elif isinstance(exc, httpx.TimeoutException):
        mensaje = "Tiempo de espera agotado conectando con el servidor"
    elif isinstance(exc, httpx.HTTPError):
        mensaje = "Falló la comunicación HTTPS con el servidor"
    elif isinstance(exc, (ErrorConsola, ValueError, OSError)):
        mensaje = str(exc)
    else:
        mensaje = "Error inesperado (consultar logs locales, sin mostrar claves ni tokens)"
    consola.print(Panel(f"[red]{mensaje}[/]", title="Operación fallida", border_style="red"))


def mostrar_identidades() -> list[IdentidadLocal]:
    cuentas = encontrar_identidades()
    if not cuentas:
        consola.print("[yellow]No hay pares .crt/.key disponibles.[/] "
                      "Genera un certificado desde la opción 2 o importa uno válido.")
        return []
    if len(cuentas) > 30:
        filtro = Prompt.ask(
            f"Hay {len(cuentas)} certificados: filtra por usuario/dispositivo (Enter = todos)",
            default="").strip().casefold()
        if filtro:
            cuentas = [c for c in cuentas if filtro in c.usuario.casefold()
                       or filtro in c.dispositivo.casefold()]
            if not cuentas:
                consola.print("[yellow]Ningún certificado coincide con ese filtro.[/]")
                return []
    tabla = Table(title="Identidades locales detectadas", box=box.ROUNDED)
    tabla.add_column("Nº", style="bright_cyan", justify="right")
    tabla.add_column("Usuario")
    tabla.add_column("Dispositivo")
    tabla.add_column("Certificado (sin clave privada)")
    for i, identidad in enumerate(cuentas, 1):
        tabla.add_row(str(i), identidad.usuario, identidad.dispositivo, identidad.certificado.name)
    consola.print(tabla)
    return cuentas


def elegir_identidad() -> IdentidadLocal | None:
    cuentas = mostrar_identidades()
    if not cuentas:
        return None
    numero = Prompt.ask("Selecciona un certificado (0 = cancelar)", default="1")
    if not numero.isdecimal() or int(numero) > len(cuentas):
        consola.print("[red]Selección inválida[/]")
        return None
    if int(numero) == 0:
        return None
    return cuentas[int(numero)-1]


def login_interactivo(cliente: ClienteConsola) -> bool:
    if cliente.conectado:
        consola.print("[yellow]Ya tienes una sesión activa. Ciérrala antes de iniciar otra.[/]")
        return False
    identidad = elegir_identidad()
    if identidad is None:
        return False
    consola.print(f"[cyan]Autenticando[/] a [bold]{identidad.usuario}[/] "
                  f"desde [bold]{identidad.dispositivo}[/]")
    password = getpass.getpass("Contraseña corporativa (oculta): ")
    try:
        with consola.status("Verificando conexión mTLS, desafío firmado y credenciales..."):
            resultado = cliente.iniciar_sesion(identidad, password)
    finally:
        del password
    consola.print(Panel(
        f"[green]HTTP {resultado['codigo']} · SESIÓN INICIADA[/]\n"
        f"Usuario: {resultado['usuario']}\nDispositivo: {resultado['dispositivo']}\n"
        f"Caduca: {resultado['expira']}\n"
        "[dim]Token almacenado solo en memoria y nunca mostrado.[/]",
        border_style="green", title="Inicio de sesión correcto"))
    return True


def consultar_interactivo(cliente: ClienteConsola) -> None:
    datos = cliente.consultar_sesion()
    tabla = Table(title="Sesión validada por el servidor", box=box.ROUNDED)
    tabla.add_column("Campo", style="cyan")
    tabla.add_column("Valor")
    for etiqueta, campo in [("Usuario", "username"), ("Dispositivo", "device_id"),
                            ("Perfil", "role"), ("Expira", "expires_at")]:
        tabla.add_row(etiqueta, str(datos.get(campo, "-")))
    consola.print(tabla)
    consola.print("[green]HTTP 200 · Sesión autorizada mediante mTLS y token[/]")


def recurso_interactivo(cliente: ClienteConsola) -> None:
    """Evidencia de acceso a recurso y envío de datos sobre mTLS 1.3."""
    documento = cliente.consultar_recurso()
    consola.print(Panel(
        f"Recurso: {documento.get('recurso', '-') }\n"
        f"Contenido: {documento.get('contenido', '-')}\n"
        f"Usuario autorizado: {documento.get('username', '-')}\n"
        f"Rol: {documento.get('role', '-')}",
        title="Camino A · GET protegido · HTTP 200", border_style="green"))
    enviar_mensaje_interactivo(cliente)



def enviar_mensaje_interactivo(cliente: ClienteConsola) -> None:
    """Envío real de texto que escribe el usuario; TLS 1.3/mTLS aplica el cifrado."""
    if not cliente.conectado:
        raise ErrorConsola("Antes debes iniciar sesión con un certificado válido (opción 5)")
    consola.print("[cyan]Escribe el mensaje que quieres enviar a Ubuntu (máximo 2048 caracteres).[/]")
    mensaje = Prompt.ask("Mensaje seguro", default="Prueba BYODSEC por TLS 1.3 y mTLS")
    if not mensaje.strip():
        raise ErrorConsola("El mensaje no puede estar vacío")
    eco = cliente.enviar_mensaje_seguro(mensaje)
    consola.print(Panel(
        f"[bold]Mensaje enviado:[/] {escape(mensaje)}\n"
        f"[bold]Servidor:[/] Ubuntu WSL2 · TLS 1.3/mTLS\n"
        f"[bold]Procesado por:[/] {escape(str(eco['username']))}\n"
        f"[bold]Bytes confirmados:[/] {eco['bytes']}\n"
        f"[bold]SHA-256 recibido y verificado:[/] {eco['sha256']}\n"
        "[green]HTTP 200: el servidor ha procesado realmente el mensaje.[/]",
        title="Camino A · POST /api/v1/resources/echo", border_style="green"))
    consola.print("[dim]El texto se muestra aquí a propósito para la demostración. "
                  "La captura de red no debe revelar su contenido en claro.[/]")


def _herramienta_wsl(modulo: str, args: list[str], titulo: str, timeout: int = 120) -> None:
    consola.print(f"[cyan]{escape(titulo)}[/]")
    with consola.status("Consultando el servicio de laboratorio en WSL..."):
        resultado = ejecutar_en_wsl(modulo, args, tiempo_maximo=timeout)
    if resultado.stdout:
        consola.print(escape(resultado.stdout[-16000:]))
    if resultado.stderr:
        consola.print(f"[yellow]{escape(resultado.stderr[-2500:])}[/]")
    if resultado.returncode != 0:
        consola.print(f"[red]Comprobación no superada (código {resultado.returncode})[/]")
    else:
        consola.print("[green]Herramienta terminada correctamente; comprueba los resultados anteriores.[/]")


def _captura_iniciar(captura: CapturaTLSServidor) -> None:
    interfaces = captura.interfaces()
    if not interfaces:
        raise ErrorConsola("No aparecen interfaces Npcap. Instala Npcap y reinicia Wireshark")
    tabla = Table(title="Origen de captura", box=box.ROUNDED)
    tabla.add_column("Nº")
    tabla.add_column("Descripción")
    for numero, descripcion in interfaces:
        tabla.add_row(numero, escape(descripcion))
    consola.print(tabla)
    consola.print("[green]Para Windows → Ubuntu WSL, elige WSL: captura donde llega el tráfico.[/]")
    numero = Prompt.ask("Origen de captura", default="WSL")
    ruta = captura.iniciar(numero)
    consola.print(Panel(f"[green]Captura iniciada[/]\nArchivo: {escape(str(ruta))}\n"
                         "Ahora inicia sesión o envía un mensaje desde el cliente.",
                         title="Wireshark · TLS 1.3/mTLS"))


def _captura_parar(captura: CapturaTLSServidor) -> None:
    ruta, tramas = captura.detener()
    consola.print(f"[cyan]Archivo guardado:[/] {escape(str(ruta))}")
    consola.print(f"[cyan]Paquetes TCP 9443 detectados:[/] {tramas}")
    if tramas == 0:
        consola.print("[yellow]Captura sin paquetes TCP 9443: NO es evidencia suficiente. "
                      "La captura no es válida; comprueba que el mensaje se ha enviado mientras capturabas.[/]")
    else:
        consola.print("[green]Se ha capturado tráfico de aplicación real. "
                      "En Wireshark aplica tcp.port == 9443 y busca TLS Application Data.[/]")
    if tramas > 0 and Confirm.ask("¿Abrir el archivo ahora en Wireshark?", default=True):
        captura.abrir_wireshark(ruta)


def menu_laboratorio(cliente: ClienteConsola, registro_url: str, ca: Path,
                     captura: CapturaTLSServidor) -> None:
    """Pruebas reales, no mock, desde una única consola interactiva."""
    while True:
        consola.print(Panel(
            "[bold cyan]1[/]  Crear usuario corporativo (administración LOCAL WSL)\n"
            "[bold cyan]2[/]  Generar certificado para un dispositivo\n"
            "[bold cyan]3[/]  Iniciar sesión segura\n"
            "[bold cyan]4[/]  Enviar MI MENSAJE cifrado y comprobar respuesta\n"
            "[bold cyan]5[/]  Iniciar captura de tráfico TLS con TShark/Npcap\n"
            "[bold cyan]6[/]  Detener captura y abrir en Wireshark\n"
            "[bold cyan]7[/]  Verificar firma y vinculación de certificado\n"
            "[bold cyan]8[/]  Comprobar TLS 1.3 y versiones rechazadas\n"
            "[bold cyan]9[/]  Auditar los 300 usuarios y certificados\n"
            "[bold cyan]10[/] Mantener hasta 300 sesiones mTLS simultáneas\n"
            "[bold cyan]11[/] Cerrar sesión y comprobar HTTP 401\n"
            "[bold cyan]12[/] Demo guiada: captura, login, mensaje y logout\n"
            "[bold cyan]13[/] Simular accesos no autorizados\n"
            "[bold cyan]14[/] Exportar auditoría a CSV\n"
            "[bold cyan]0[/]  Volver al menú principal",
            title="PRUEBAS Y WIRESHARK", border_style="bright_cyan"))
        opcion = Prompt.ask("Prueba", choices=[str(i) for i in range(15)], default="4")
        if opcion == "0":
            return
        try:
            if opcion == "1":
                crear_usuario_interactivo()
            elif opcion == "2":
                emitir_certificado_usuario_interactivo(registro_url, ca)
            elif opcion == "3":
                login_interactivo(cliente)
            elif opcion == "4":
                enviar_mensaje_interactivo(cliente)
            elif opcion == "5":
                _captura_iniciar(captura)
            elif opcion == "6":
                _captura_parar(captura)
            elif opcion == "7":
                ident = elegir_identidad()
                if ident is not None:
                    # Herramienta existente: no imprime contenido de la clave privada.
                    from tools.verificar_certificado_real import comprobar
                    ok = comprobar(ident.dispositivo)
                    if not ok:
                        consola.print("[red]La verificación del certificado no ha pasado.[/]")
            elif opcion == "8":
                _herramienta_wsl("tools.comprobar_tls", ["--sin-access-server", "--json",
                                 "evidencias/logs/prueba_tls_desde_cliente.json"],
                                 "Negociación TLS real y rechazo de versiones anteriores", 160)
            elif opcion == "9":
                _herramienta_wsl("tools.auditar_rf1_rf5_pki", ["--total", "300", "--json",
                                 "evidencias/logs/prueba_rf5_desde_cliente.json"],
                                 "Usuarios, roles, certificados y vínculos", 160)
            elif opcion == "10":
                cantidad = Prompt.ask("Usuarios con sesiones a la vez", choices=["10", "50", "100", "200", "300"], default="10")
                segundos = Prompt.ask("Segundos manteniendo todas las sesiones (5-120)", default="30")
                if not segundos.isdecimal() or not 5 <= int(segundos) <= 120:
                    consola.print("[red]La duración debe estar entre 5 y 120 segundos.[/]")
                    continue
                if not Confirm.ask(f"¿Autenticar {cantidad} usuarios y mantener sus sesiones durante {segundos}s?", default=False):
                    continue
                consola.print("[cyan]La carga corre en Ubuntu WSL. Verás el avance y el resultado real aquí.[/]")
                consola.print("[dim]Esta operación puede tardar varios minutos; no cierres el servidor.[/]")
                resultado = ejecutar_en_wsl(
                    "tools.carga_300_sesiones",
                    ["--usuarios", cantidad, "--duracion", segundos, "--preparacion", "360",
                     "--json", f"bench/resultados/sesiones_{cantidad}.json"],
                    interactivo=True, tiempo_maximo=750)
                if resultado.returncode == 0:
                    consola.print("[bold green]PRUEBA SUPERADA: usuarios autenticados y mensajes verificados simultáneamente.[/]")
                else:
                    consola.print("[bold red]No se han demostrado todas las sesiones simultáneas.[/] Revisa el JSON de resultados.")
            elif opcion == "11":
                logout_interactivo(cliente)
            elif opcion == "12":
                if cliente.conectado:
                    consola.print("[yellow]Cierra antes tu sesión activa para repetir el ciclo completo.[/]")
                    continue
                if Confirm.ask("¿Iniciar captura con Wireshark?", default=True):
                    _captura_iniciar(captura)
                try:
                    if login_interactivo(cliente):
                        consultar_interactivo(cliente)
                        enviar_mensaje_interactivo(cliente)
                        logout_interactivo(cliente)
                finally:
                    if captura.activa:
                        _captura_parar(captura)
            elif opcion == "13":
                if Confirm.ask("¿Ejecutar seis intentos de acceso NO autorizados al gateway local?", default=False):
                    _herramienta_wsl("tools.ataques_vpn_real", ["--json",
                                     "evidencias/ataques/prueba_ataques_desde_cliente.json"],
                                     "Intentos de acceso rechazados por TLS/mTLS y sesiones", 200)
            elif opcion == "14":
                _herramienta_wsl("tools.exportar_auditoria_csv", [],
                                 "Exportación local de registros depurados")
        except Exception as exc:
            error_publico(exc)
        pausa()


def vpn_interactivo(cliente: ClienteConsola) -> None:
    datos = cliente.consultar_vpn()
    consola.print(Panel(
        f"Usuario: {datos.get('username', '-')}\n"
        f"Conectado: {bool(datos.get('connected'))}\n"
        f"Conexiones reales en Access Server: {datos.get('count', 0)}",
        title='VPN · Estado verificado por API REST', border_style='cyan'))
    tabla = Table(box=box.ROUNDED)
    tabla.add_column('IP de VPN')
    tabla.add_column('Cifrado de datos')
    tabla.add_column('Conectado desde')
    for c in datos.get('connections', []):
        tabla.add_row(str(c.get('vpn_ip') or '-'), str(c.get('cipher') or '-'),
                      str(c.get('connected_since') or '-'))
    consola.print(tabla)
    if not datos.get('connected'):
        consola.print('[yellow]RF2 puede estar activo sin un túnel VPN conectado.\n'
                      'Importa el perfil userlogin en OpenVPN Connect y vuelve a comprobar.[/]')


def logout_interactivo(cliente: ClienteConsola) -> None:
    if not cliente.conectado:
        consola.print("[yellow]No hay ninguna sesión iniciada.[/]")
        return
    if not Confirm.ask("¿Cerrar sesión y comprobar que el token queda revocado?", default=True):
        return
    with consola.status("Revocando sesión y comprobando su rechazo posterior..."):
        resultado = cliente.cerrar_sesion(comprobar_revocacion=True)
    consola.print("[green]✓[/] Cierre de sesión: HTTP 200 · Sesión revocada en el servidor")
    consola.print("[green]✓[/] Token local descartado y conexión HTTPS cerrada")
    if resultado.rechazo_comprobado:
        consola.print("[green]✓[/] Reutilización del token: HTTP 401 (rechazo esperado)")
    elif resultado.rechazo_comprobado is False:
        consola.print(f"[bold red]ALERTA: rechazo NO demostrado (HTTP {resultado.codigo_comprobacion})[/]")
    consola.print("[dim]Con integración VPN activada, el servidor también solicita la desconexión por REST.[/]")


def estadisticas_rf5() -> None:
    from src.rf5.gestion import resumen_usuarios
    resumen = resumen_usuarios()
    tabla = Table(title="Usuarios corporativos", box=box.ROUNDED)
    tabla.add_column("Indicador", style="cyan")
    tabla.add_column("Valor", justify="right")
    for nombre, valor in [
        ("Cuentas precargadas", resumen["total_rf5"]),
        ("Cuentas activas", resumen["usuarios_activos"]),
        ("Certificados vinculados", resumen["certificados_emitidos"]),
    ]:
        tabla.add_row(nombre, str(valor))
    for rol, cantidad in sorted(resumen["por_rol"].items()):
        tabla.add_row("Rol " + rol, str(cantidad))
    consola.print(tabla)
    consola.print("[dim]No se muestran contraseñas ni hashes.[/]")


def auditoria() -> None:
    for titulo, ruta in [("Registro de dispositivos", RUTA_LOG_RF1), ("Cierres de sesión", RUTA_LOG_RF4)]:
        tabla = Table(title=titulo, box=box.SIMPLE_HEAVY)
        for columna in ("Fecha UTC", "Evento", "Usuario", "Dispositivo"):
            tabla.add_column(columna)
        if ruta.exists():
            with ruta.open("r", encoding="utf-8", errors="replace") as archivo:
                ultimas = deque(archivo, maxlen=8)
            for linea in ultimas:
                try:
                    dato = json.loads(linea)
                    tabla.add_row(*(str(dato.get(k, "-"))[:60]
                                    for k in ("timestamp", "event", "username", "device_id")))
                except (ValueError, AttributeError):
                    continue
        consola.print(tabla)
        if not ruta.exists():
            consola.print(f"[dim]Sin eventos todavía: {ruta.name}[/]")



def crear_usuario_interactivo() -> None:
    """Alta de laboratorio mediante comando administrativo LOCAL de Ubuntu WSL.

    No existe ningún endpoint público para crear cuentas. Se requiere acceso
    local a la distribución de WSL y a la base corporativa del proyecto.
    """
    consola.print(Panel(
        "Crear una cuenta corporativa NUEVA directamente en la base del servidor WSL.\n"
        "La contraseña se introducirá oculta en la consola de Ubuntu.\n"
        "[yellow]Acción administrativa LOCAL: no se expone por HTTPS a otros usuarios.[/]",
        title="Alta corporativa · Administrador local", border_style="cyan"))
    if not Confirm.ask("¿Deseas dar de alta un usuario en tu entorno de laboratorio?", default=False):
        return
    usuario = Prompt.ask("Nombre de usuario NUEVO").strip()
    rol = Prompt.ask("Perfil corporativo", choices=["PDI", "PAS", "INVESTIGADOR"], default="PDI")
    if crear_usuario_corporativo(usuario, rol):
        consola.print(Panel(
            f"[green]Usuario creado correctamente[/]\n"
            f"Usuario: {escape(usuario)}\nRol: {rol}\n"
            "[dim]Selecciona ahora la opción 2 para generar el certificado del nuevo dispositivo.[/]",
            border_style="green", title="Alta confirmada"))
    else:
        consola.print("[red]No se creó el usuario. Comprueba el error mostrado por Ubuntu WSL.[/]")


def emitir_certificado_usuario_interactivo(registro_url: str, ca: Path) -> None:
    """Un usuario ya existente puede registrar un dispositivo adicional con RF1."""
    consola.print("[cyan]Generar certificado[/] El usuario debe existir y el dispositivo ser nuevo.")
    registro_rf1(registro_url, ca)


def registro_rf1(url_registro: str, ca: Path) -> None:
    consola.print(Panel(
        "Registra un dispositivo NUEVO mediante el servidor HTTPS :8444.\n"
        "Se generará una clave privada RSA 3072 local sin sobrescribir claves existentes.\n"
        "[yellow]La clave no estará cifrada en reposo: uso exclusivo de laboratorio.[/]",
        title="Certificado para un dispositivo nuevo", border_style="cyan"))
    usuario = Prompt.ask("Usuario corporativo").strip()
    dispositivo = Prompt.ask("Identificador NUEVO de dispositivo").strip()
    password = getpass.getpass("Contraseña corporativa (oculta): ")
    try:
        with consola.status("Generando clave y solicitando certificado al servidor de registro..."):
            identidad = registrar_dispositivo(
                usuario=usuario, password=password, device_id=dispositivo,
                url_registro=url_registro, ca=ca)
    finally:
        del password
    consola.print(Panel(
        f"[green]HTTP 201 · Certificado emitido correctamente[/]\n"
        f"Usuario: {identidad.usuario}\nDispositivo: {identidad.dispositivo}\n"
        f"Certificado: {identidad.certificado}\n"
        "[dim]Clave privada guardada localmente y excluida de Git. Ya puedes iniciar sesión.[/]",
        border_style="green"))


def demo_completa(cliente: ClienteConsola) -> None:
    consola.print("[bold]Demostración: iniciar sesión → consultar → comunicar → cerrar → HTTP 401[/]")
    if cliente.conectado:
        consola.print("[yellow]Primero cierra la sesión activa para ejecutar el ciclo completo.[/]")
        return
    if not login_interactivo(cliente):
        return
    try:
        consultar_interactivo(cliente)
        if os.getenv("BYODSEC_VPN_REST") != "1":
            recurso_interactivo(cliente)
        # No hay prompts: demostración continua; el usuario seleccionó previamente el modo demo.
        with consola.status("Cerrando sesión y probando token revocado..."):
            resultado = cliente.cerrar_sesion(comprobar_revocacion=True)
        if resultado.rechazo_comprobado:
            consola.print(Panel("[green]Inicio de sesión: HTTP 200\n"
                                 "Consulta de sesión: HTTP 200\n"
                                 "Cierre de sesión: HTTP 200\n"
                                 "Acceso posterior: HTTP 401 (correcto)[/]",
                                 border_style="green", title="Ciclo completo SUPERADO"))
        else:
            consola.print(Panel(f"[red]El servidor no rechazó el token anterior "
                                 f"(HTTP {resultado.codigo_comprobacion}); revisar la revocación.[/]",
                                 border_style="red", title="Error de seguridad"))
    except Exception:
        # Si el logout falló, mantener la sesión para reintentar o cerrarla manualmente.
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="BYODSEC: cliente de acceso corporativo seguro")
    parser.add_argument("--url", default="https://localhost:9443", help="Gateway con mTLS")
    parser.add_argument("--registro-url", default="https://localhost:8444", help="Registro de dispositivos con TLS")
    parser.add_argument("--ca", type=Path, default=CA_DEFECTO, help="CA pública confiable")
    args = parser.parse_args()
    cliente = ClienteConsola(url=args.url, ca=args.ca)
    captura = CapturaTLSServidor()
    try:
        while True:
            cabecera(cliente)
            opcion = Prompt.ask("Selecciona una opción", choices=[str(i) for i in range(12)], default="5")
            if opcion == "0":
                if cliente.conectado:
                    consola.print("[yellow]Hay una sesión activa.[/]")
                    if Confirm.ask("¿Cerrar sesión antes de salir?", default=True):
                        try:
                            logout_interactivo(cliente)
                        except Exception as exc:
                            error_publico(exc)
                            if not Confirm.ask("¿Salir sin revocación confirmada?", default=False):
                                pausa()
                                continue
                    else:
                        if not Confirm.ask("Salir sin logout del servidor?", default=False):
                            continue
                break
            try:
                if opcion == "1":
                    crear_usuario_interactivo()
                elif opcion == "2":
                    emitir_certificado_usuario_interactivo(args.registro_url, args.ca)
                elif opcion == "3":
                    estadisticas_rf5()
                elif opcion == "4":
                    mostrar_identidades()
                elif opcion == "5":
                    login_interactivo(cliente)
                elif opcion == "6":
                    consultar_interactivo(cliente)
                elif opcion == "7":
                    if os.getenv("BYODSEC_VPN_REST") == "1":
                        vpn_interactivo(cliente)
                    else:
                        recurso_interactivo(cliente)
                elif opcion == "8":
                    logout_interactivo(cliente)
                elif opcion == "9":
                    demo_completa(cliente)
                elif opcion == "10":
                    menu_laboratorio(cliente, args.registro_url, args.ca, captura)
                elif opcion == "11":
                    auditoria()
            except Exception as exc:
                error_publico(exc)
            pausa()
    except (KeyboardInterrupt, EOFError):
        consola.print("\n[yellow]Interfaz interrumpida; no se garantiza logout del servidor.[/]")
    finally:
        captura.cerrar()
        cliente.desconectar_local()
        consola.print("[dim]Cliente cerrado. Tokens locales descartados; claves privadas conservadas.[/]")


if __name__ == "__main__":
    main()
