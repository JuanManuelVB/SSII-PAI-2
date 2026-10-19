@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0vpn\scripts\lanzador_seguro.ps1"
set "CODIGO=%ERRORLEVEL%"
if not "%CODIGO%"=="0" (
  echo.
  echo [BYODSEC] No se ha podido iniciar el laboratorio. Revisa el mensaje anterior.
  pause
)
exit /b %CODIGO%
