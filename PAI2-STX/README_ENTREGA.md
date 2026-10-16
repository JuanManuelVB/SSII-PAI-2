# BYODSEC: paquete de integración segura (PAI-2)

**Empieza por `docs/PLAN_CUMPLIMIENTO_COMPLETO.md`**. No hay claves privadas ni datos SQLite reales en este ZIP. Lee la matriz final y realiza las pruebas en tu Windows/WSL con la CA local.

Arranque REST: `python -m src.vpn_rest_as.ejecutar` (no simultanear con `src.gateway.ejecutar` en el mismo puerto). Menú: `python -m src.client.interfaz` con `BYODSEC_VPN_REST=1`.
