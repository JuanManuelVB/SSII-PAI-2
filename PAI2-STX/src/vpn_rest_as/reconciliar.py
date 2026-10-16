"""Reconciliación REST de sesiones VPN caducadas, revocadas o bloqueadas.

Ejecutar periódicamente mediante systemd timer. Ante incertidumbre REST
no anuncia desconexión: devuelve error y permite reintentar.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from src.common.base_datos import RUTA_BASE_DATOS_POR_DEFECTO, conectar_base_datos
from src.vpn_rest_as.autorizaciones import inicializar, bloquear_concesiones_usuario
from src.vpn_rest_as.client import AccessServerClient, ConfigAccessServer, AccessServerError


def usuarios_sin_sesion_valida(ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO) -> list[str]:
    inicializar(ruta)
    ahora=datetime.now(timezone.utc).isoformat()
    with conectar_base_datos(ruta) as db:
        rows=db.execute("""SELECT DISTINCT g.username FROM vpn_grants g
            LEFT JOIN sessions s ON s.token_hash=g.token_hash
            LEFT JOIN users u ON u.username=g.username
            LEFT JOIN device_pairings d ON d.device_id=g.device_id
            WHERE g.disabled_at IS NULL
              AND (s.token_hash IS NULL OR s.revoked_at IS NOT NULL OR
                   s.expires_at <= ? OR u.status != 'active' OR
                   d.status != 'active' OR d.username != g.username)
            """,(ahora,)).fetchall()
    return [r['username'] for r in rows]


def ejecutar(servicio=None, ruta: Path = RUTA_BASE_DATOS_POR_DEFECTO):
    usuarios=usuarios_sin_sesion_valida(ruta)
    if not usuarios:
        return []
    if servicio is None:
        servicio=AccessServerClient(ConfigAccessServer.desde_entorno())
    hechos=[]
    for username in usuarios:
        # Se bloquea antes de terminar el túnel.
        servicio.fijar_acceso(username, permitido=False)
        try:
            servicio.desconectar_usuario(username)
        except AccessServerError:
            # Si no hay clientes, el bloqueo ya previene reconexiones, pero
            # exigimos comprobación explícita de que no quedan activos.
            if servicio.conexiones_usuario(username):
                raise
        bloquear_concesiones_usuario(username, ruta)
        hechos.append(username)
    return hechos


if __name__ == '__main__':
    completados=ejecutar()
    print('Cuentas cerradas por expiración o revocación:',len(completados))
