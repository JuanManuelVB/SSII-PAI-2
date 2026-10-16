"""Adaptador Uvicorn HTTP/1.1: expone SOLO el certificado verificado por TLS.

El certificado se lee del socket SSL; jamás de cabeceras HTTP suministradas
por un cliente. Si el servidor se arranca con el protocolo estándar, RF2/RF4
rechazan las peticiones: fallan de forma segura.
"""

from __future__ import annotations

import asyncio

from uvicorn.protocols.http.h11_impl import H11Protocol


class MTLSH11Protocol(H11Protocol):
    def connection_made(self, transport: asyncio.Transport) -> None:
        super().connection_made(transport)
        objeto_ssl = transport.get_extra_info("ssl_object")
        certificado = objeto_ssl.getpeercert(binary_form=True) if objeto_ssl else None
        aplicacion_original = self.app

        async def aplicacion_con_identidad(scope, receive, send):
            if scope["type"] == "http" and certificado:
                scope["mtls_client_cert_der"] = certificado
            await aplicacion_original(scope, receive, send)

        self.app = aplicacion_con_identidad
