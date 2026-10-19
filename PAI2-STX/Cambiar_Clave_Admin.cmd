@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0vpn\scripts\lanzador_seguro.ps1" -SoloGuardar -Reconfigurar
if errorlevel 1 pause
