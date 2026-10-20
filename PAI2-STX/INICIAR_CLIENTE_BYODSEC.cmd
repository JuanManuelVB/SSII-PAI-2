@echo off
setlocal EnableExtensions
chcp 65001 >nul
TITLE BYODSEC - CLIENTE (Windows)
pushd "%~dp0" || (
  echo ERROR: No se puede abrir la carpeta de BYODSEC.
  pause
  exit /b 1
)
if not exist "src\client\interfaz.py" (
  echo ERROR: Extrae los archivos en la RAIZ de PAI2-STX.
  popd
  pause
  exit /b 1
)
if not exist "pki\ca\ca.crt" (
  echo ERROR: Falta pki\ca\ca.crt. No se regeneraran certificados automaticamente.
  popd
  pause
  exit /b 1
)
set "BYODSEC_VPN_REST="
set "BYODSEC_VPN_DEFAULT_DENY="
echo ===================================================
echo     BYODSEC  -  CLIENTE CAMINO A (Windows)
echo ===================================================
echo [1] Registrar dispositivo / emitir certificado RF1
 echo [2] Login con certificado y contrasena RF2
 echo [7] Demo RF2 + recurso + RF4
 echo [8] Ver certificados locales
 echo [9] Enviar datos cifrados al servidor
 echo [10] CENTRO DE PRUEBAS: crear usuarios, mensajes y Wireshark
 echo.
py -m src.client.interfaz --url https://localhost:9443 --registro-url https://localhost:8444
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo ERROR al abrir el cliente. Comprueba Python y dependencias.
  echo   py -m pip install -r requirements.txt
)
popd
echo.
echo Pulsa una tecla para cerrar la ventana.
pause >nul
exit /b %RC%
