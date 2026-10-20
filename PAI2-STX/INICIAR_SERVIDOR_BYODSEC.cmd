@echo off
setlocal EnableExtensions
chcp 65001 >nul
TITLE BYODSEC - SERVIDOR (Ubuntu WSL2)
pushd "%~dp0" || (
  echo ERROR: No se puede abrir la carpeta de BYODSEC.
  pause
  exit /b 1
)
if not exist "src\gateway\ejecutar.py" (
  echo ERROR: Extrae los archivos en la RAIZ de PAI2-STX, no en una subcarpeta.
  popd
  pause
  exit /b 1
)
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: No encuentro WSL2. Comprueba que Ubuntu WSL esta instalado.
  popd
  pause
  exit /b 1
)
echo ===================================================
echo     BYODSEC  -  SERVIDOR CAMINO A (Ubuntu WSL2)
echo ===================================================
echo Se iniciaran simultaneamente:
echo   HTTPS/mTLS: https://localhost:9443
 echo   Alta RF1:   https://localhost:8444
 echo.
echo Mantener esta ventana abierta. Para parar, Ctrl+C.
echo.
wsl.exe -- bash scripts/iniciar_servidor_camino_a.sh
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo El servidor termino con codigo %RC%.
popd
echo.
echo Pulsa una tecla para cerrar la ventana.
pause >nul
exit /b %RC%
