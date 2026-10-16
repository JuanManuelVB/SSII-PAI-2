"""Interfaz de consola interactiva BYODSEC.

Ejecutar desde PAI2-STX:  py -m src.client.interfaz
Requiere 'rich':             py -m pip install -r requirements-interfaz.txt
No sustituye a los servidores: iniciar gateway mTLS en otra terminal.
"""
from __future__ import annotations

import argparse
import getpass
import json
from collections import deque
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich import box
except ImportError as exc:
    raise SystemExit("Falta 'rich'. Instala: py -m pip install -r requirements-interfaz.txt") from exc

from src.client.servicio_consola import (
    CA_DEFECTO,
    RAIZ,
    ClienteConsola,
    ErrorConsola,
    IdentidadLocal,
    encontrar_identidades,
    registrar_dispositivo,
)

consola = Console()
RUTA_LOG_RF4 = RAIZ / "evidencias" / "logs" / "rf4-audit.jsonl"
RUTA_LOG_RF1 = RAIZ / "evidencias" / "logs" / "rf1-audit.jsonl"


def cabecera(cliente: ClienteConsola) -> None:
    consola.clear()
    consola.print(Panel.fit(
        "[bold bright_cyan]BYODSEC[/]  [white]· Universidad U-Secure[/]\n"
        "[dim]Cliente de laboratorio TLS 1.3 / mTLS · RF1 · RF2 · RF4 · RF5[/]",
        border_style="bright_cyan", padding=(1, 3)))
    if cliente.conectado:
        consola.print(f"[green]● SESIÓN ACTIVA[/]   Usuario: [bold]{cliente.usuario}[/]   "
                      f"Caduca: {cliente.caducidad or '-'}")
    else:
        consola.print("[yellow]● SIN SESIÓN[/]  [dim]Gateway de acceso: " + cliente.url + "[/]")
    tabla = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    for num, titulo, descripcion in [
        ("1", "RF1  Registrar dispositivo", "requiere servidor de registro :8444"),
        ("2", "RF2  Iniciar sesión", "usuario + contraseña + certificado"),
        ("3", "RF2  Consultar sesión", "GET /sessions/me"),
        ("4", "RF4  Cerrar sesión", "revocación + prueba de HTTP 401"),
        ("5", "RF5  Usuarios corporativos", "estadísticas locales de SQLite"),
        ("6", "Auditoría", "eventos RF1 y RF4 sin secretos"),
        ("7", "Demostración completa", "login → consulta → logout → 401"),
        ("8", "Inspeccionar certificados", "certificados de cliente en el equipo"),
        ("0", "Salir", "cerrar cliente TLS"),
    ]:
        tabla.add_row(f"[bold cyan][{num}][/]", titulo, f"[dim]{descripcion}[/]")
    consola.print(tabla)


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
                      "Emite certificados desde RF5 o registra un dispositivo con RF1.")
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
    consola.print(f"[cyan]RF2[/] Iniciando sesión para [bold]{identidad.usuario}[/] "
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
        border_style="green", title="RF2 correcto"))
    return True


def consultar_interactivo(cliente: ClienteConsola) -> None:
    datos = cliente.consultar_sesion()
    tabla = Table(title="RF2 · Sesión validada por el servidor", box=box.ROUNDED)
    tabla.add_column("Campo", style="cyan")
    tabla.add_column("Valor")
    for etiqueta, campo in [("Usuario", "username"), ("Dispositivo", "device_id"),
                            ("Perfil", "role"), ("Expira", "expires_at")]:
        tabla.add_row(etiqueta, str(datos.get(campo, "-")))
    consola.print(tabla)
    consola.print("[green]HTTP 200 · Sesión autorizada mediante mTLS y token[/]")


def logout_interactivo(cliente: ClienteConsola) -> None:
    if not cliente.conectado:
        consola.print("[yellow]No hay ninguna sesión iniciada.[/]")
        return
    if not Confirm.ask("¿Cerrar sesión y comprobar que el token queda revocado?", default=True):
        return
    with consola.status("Revocando sesión RF4 y comprobando su rechazo posterior..."):
        resultado = cliente.cerrar_sesion(comprobar_revocacion=True)
    consola.print("[green]✓[/] RF4 logout: HTTP 200 · Sesión revocada en el servidor")
    consola.print("[green]✓[/] Token local descartado y conexión HTTPS cerrada")
    if resultado.rechazo_comprobado:
        consola.print("[green]✓[/] Reutilización del token: HTTP 401 (rechazo esperado)")
    elif resultado.rechazo_comprobado is False:
        consola.print(f"[bold red]ALERTA: rechazo NO demostrado (HTTP {resultado.codigo_comprobacion})[/]")
    consola.print("[dim]En modo BYODSEC_VPN_REST=1, el servidor solicita bloqueo y desconexión de la VPN por REST.[/]")


def estadisticas_rf5() -> None:
    from src.rf5.gestion import resumen_usuarios
    resumen = resumen_usuarios()
    tabla = Table(title="RF5 · Usuarios corporativos en SQLite", box=box.ROUNDED)
    tabla.add_column("Indicador", style="cyan")
    tabla.add_column("Valor", justify="right")
    for nombre, valor in [
        ("Cuentas RF5", resumen["total_rf5"]),
        ("Cuentas activas", resumen["usuarios_activos"]),
        ("Certificados vinculados", resumen["certificados_emitidos"]),
    ]:
        tabla.add_row(nombre, str(valor))
    for rol, cantidad in sorted(resumen["por_rol"].items()):
        tabla.add_row("Rol " + rol, str(cantidad))
    consola.print(tabla)
    consola.print("[dim]No se muestran contraseñas ni hashes.[/]")


def auditoria() -> None:
    for titulo, ruta in [("RF1 · Registro", RUTA_LOG_RF1), ("RF4 · Cierres", RUTA_LOG_RF4)]:
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


def registro_rf1(url_registro: str, ca: Path) -> None:
    consola.print(Panel(
        "Registra un dispositivo NUEVO con el servicio RF1 en HTTPS :8444.\n"
        "Se generará una clave privada RSA 3072 local sin sobrescribir claves existentes.\n"
        "[yellow]La clave no estará cifrada en reposo: uso exclusivo de laboratorio.[/]",
        title="RF1 · Emparejamiento", border_style="cyan"))
    usuario = Prompt.ask("Usuario corporativo").strip()
    dispositivo = Prompt.ask("Identificador NUEVO de dispositivo").strip()
    password = getpass.getpass("Contraseña corporativa (oculta): ")
    try:
        with consola.status("Generando clave y solicitando certificado al servidor RF1..."):
            identidad = registrar_dispositivo(
                usuario=usuario, password=password, device_id=dispositivo,
                url_registro=url_registro, ca=ca)
    finally:
        del password
    consola.print(Panel(
        f"[green]HTTP 201 · Certificado RF1 emitido[/]\n"
        f"Usuario: {identidad.usuario}\nDispositivo: {identidad.dispositivo}\n"
        f"Certificado: {identidad.certificado}\n"
        "[dim]Clave privada guardada localmente y excluida de Git. Ya puedes iniciar sesión.[/]",
        border_style="green"))


def demo_completa(cliente: ClienteConsola) -> None:
    consola.print("[bold]Demostración: RF2 login → RF2 /me → RF4 logout → HTTP 401[/]")
    if cliente.conectado:
        consola.print("[yellow]Primero cierra la sesión activa para ejecutar el ciclo completo.[/]")
        return
    if not login_interactivo(cliente):
        return
    try:
        consultar_interactivo(cliente)
        # No hay prompts: demostración continua; el usuario seleccionó previamente el modo demo.
        with consola.status("Cerrando sesión y probando token revocado..."):
            resultado = cliente.cerrar_sesion(comprobar_revocacion=True)
        if resultado.rechazo_comprobado:
            consola.print(Panel("[green]RF2 login: HTTP 200\n"
                                 "RF2 consulta: HTTP 200\n"
                                 "RF4 logout: HTTP 200\n"
                                 "RF4 acceso posterior: HTTP 401 (correcto)[/]",
                                 border_style="green", title="Ciclo completo SUPERADO"))
        else:
            consola.print(Panel(f"[red]El servidor no rechazó el token anterior "
                                 f"(HTTP {resultado.codigo_comprobacion}); revisar RF4.[/]",
                                 border_style="red", title="Error de seguridad"))
    except Exception:
        # Si el logout falló, mantener la sesión para reintentar o cerrarla manualmente.
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="BYODSEC: consola interactiva RF1 RF2 RF4 RF5")
    parser.add_argument("--url", default="https://localhost:8443", help="Gateway con mTLS")
    parser.add_argument("--registro-url", default="https://localhost:8444", help="Alta RF1 con TLS")
    parser.add_argument("--ca", type=Path, default=CA_DEFECTO, help="CA pública confiable")
    args = parser.parse_args()
    cliente = ClienteConsola(url=args.url, ca=args.ca)
    try:
        while True:
            cabecera(cliente)
            opcion = Prompt.ask("Selecciona una opción", choices=[str(i) for i in range(9)], default="2")
            if opcion == "0":
                if cliente.conectado:
                    consola.print("[yellow]Hay una sesión activa.[/]")
                    if Confirm.ask("¿Cerrar sesión RF4 antes de salir?", default=True):
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
                    registro_rf1(args.registro_url, args.ca)
                elif opcion == "2":
                    login_interactivo(cliente)
                elif opcion == "3":
                    consultar_interactivo(cliente)
                elif opcion == "4":
                    logout_interactivo(cliente)
                elif opcion == "5":
                    estadisticas_rf5()
                elif opcion == "6":
                    auditoria()
                elif opcion == "7":
                    demo_completa(cliente)
                elif opcion == "8":
                    mostrar_identidades()
            except Exception as exc:
                error_publico(exc)
            pausa()
    except (KeyboardInterrupt, EOFError):
        consola.print("\n[yellow]Interfaz interrumpida; no se garantiza logout del servidor.[/]")
    finally:
        cliente.desconectar_local()
        consola.print("[dim]Cliente cerrado. Tokens locales descartados; claves privadas conservadas.[/]")


if __name__ == "__main__":
    main()
