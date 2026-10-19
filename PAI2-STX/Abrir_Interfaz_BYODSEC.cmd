@echo off
setlocal
cd /d "%~dp0"
set "BYODSEC_VPN_REST=1"
py -m src.client.interfaz --url https://localhost:9443 --registro-url https://localhost:8444
if errorlevel 1 (
  echo.
  echo [BYODSEC] Comprueba que Windows tiene Python y las dependencias instaladas.
  pause
)
