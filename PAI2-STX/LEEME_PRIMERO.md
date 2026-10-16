# Parche REST nativa (sin socket) para BYODSEC

Este ZIP añade una ALTERNATIVA con OpenVPN **Access Server 3.2+**, no sustituye automáticamente vuestro OpenVPN Community instalado. No sobrescribe RF1, RF2, RF4 ni RF5.

**Pruebas:** `py -m pytest -q tests/test_vpn_rest_as.py`.

**Guía completa:** `docs/REST_NATIVA_Y_COMPANEROS.md`.

**Limitaciones:** Access Server gratuito permite hasta dos conexiones simultáneas; el servidor Community que ya funciona no tiene API REST nativa y sigue siendo útil para las pruebas de 300 usuarios. Los tests verifican peticiones REST simuladas, NO un despliegue Access Server real ni la integración final con las credenciales SQLite.
