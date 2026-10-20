# Qué se ha retirado y qué se ha conservado

**Retirado:** `.venv-wsl` empaquetado; copias de base SQLite; certificados y claves privadas reales; `credenciales.csv`; rastros de ejecución y datos de auditoría; archivos de cache; dependencia de `src/vpn_rest_as` (OpenVPN Access Server); herramientas de túnel IP, creación de perfiles, prueba de túnel, gestión REST AS y pruebas exclusivas VPN; scripts de instalación/monitorización de Access Server; medidas iperf/RTT propias de VPN; documentación que describía erróneamente VPN como arquitectura activa; menú CMD redundante.

**Conservado:** CA/PKI generable en local, RF1/RF2/RF4/RF5, menú ordenado, captura Wireshark/WSL, demostración real de mensajes cifrados, seguridad, auditoría y prueba de 300 sesiones con reintentos limitados y registro de errores.

**No se ha cambiado ni se han borrado los archivos locales de tu PC.** El ZIP no puede incluir tus certificados y contraseñas activos. Úsalo sobre tu proyecto actual solo tras hacer una copia de seguridad. Las dos claves `pki/ca/ca.key` y `pki/server/server.key`, el directorio `pki/clients/`, y `data/rf1.sqlite3` deben permanecer juntos y asociados a la misma CA.

**Advertencia de alcance:** Es el último proyecto completo compartido más los parches posteriores de esta conversación. No incluye posibles cambios locales todavía no compartidos.
