# Usar desde PowerShell de Windows, ANTES y DESPUES de establecer la VPN.
# Ejemplo: .\vpn\scripts\probar_conectividad.ps1 -VpnIP 10.0.10.1
param(
    [Parameter(Mandatory=$true)][string]$VpnIP,
    [int]$Port = 8080
)
$ErrorActionPreference = 'Stop'
$uri = "http://${VpnIP}:${Port}/api/v1/recurso-interno"
Write-Host "Probando: $uri" -ForegroundColor Cyan
$r = Test-NetConnection -ComputerName $VpnIP -Port $Port -WarningAction SilentlyContinue
Write-Host "TCP accesible: $($r.TcpTestSucceeded)"
if ($r.TcpTestSucceeded) {
    try {
        $respuesta = Invoke-RestMethod -Uri $uri -TimeoutSec 8
        Write-Host "REST responde: $($respuesta.estado)" -ForegroundColor Green
    } catch {
        Write-Host "TCP responde, pero REST ha fallado: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
Write-Host "Comprueba tambien la ruta elegida con: route print -4"
Write-Host "IMPORTANTE: una respuesta positiva no prueba por sí sola que se haya usado la VPN."
