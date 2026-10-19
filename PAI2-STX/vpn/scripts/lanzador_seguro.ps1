#requires -Version 5.1
<#
BYODSEC - lanzador local Windows (sin contraseñas en Git).
La contraseña de Access Server se guarda en el perfil de Windows con DPAPI
(protegida para el mismo usuario de Windows). Se introduce UNA vez.
El secreto se envía a WSL por stdin, nunca como argumento de proceso.
#>
[CmdletBinding()]
param(
    [switch] $Reconfigurar,
    [switch] $SoloGuardar
)

$ErrorActionPreference = 'Stop'
$raiz = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$directorioPrivado = Join-Path $env:LOCALAPPDATA 'BYODSEC'
$archivoPrivado = Join-Path $directorioPrivado 'openvpn_admin_dpapi.txt'

function Guardar-Clave {
    if (-not (Test-Path -LiteralPath $directorioPrivado)) {
        New-Item -ItemType Directory -Path $directorioPrivado -Force | Out-Null
    }
    Write-Host 'Introduce UNA VEZ la contraseña administrativa de OpenVPN Access Server (usuario openvpn).' -ForegroundColor Cyan
    $secreto = Read-Host 'Contraseña' -AsSecureString
    if ($secreto.Length -eq 0) { throw 'La contraseña no puede estar vacía.' }
    # Windows DPAPI del usuario actual, sin clave ni password en el repositorio.
    $cifrado = ConvertFrom-SecureString -SecureString $secreto
    [System.IO.File]::WriteAllText($archivoPrivado, $cifrado, [System.Text.Encoding]::ASCII)
    $secreto.Dispose()
    Write-Host ('Clave guardada cifrada en ' + $archivoPrivado) -ForegroundColor Green
}

if ($Reconfigurar -or -not (Test-Path -LiteralPath $archivoPrivado)) {
    Guardar-Clave
}
if ($SoloGuardar) { exit 0 }

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'No se encuentra WSL. Instala una distribución Ubuntu WSL2 antes de continuar.'
}
if (-not (Test-Path -LiteralPath (Join-Path $raiz 'src\gateway\ejecutar.py'))) {
    throw 'No se ha encontrado src/gateway/ejecutar.py. Copia el paquete en la raíz de PAI2-STX.'
}
if (-not (Test-Path -LiteralPath (Join-Path $raiz 'vpn\scripts\arrancar_servidores_seguro.sh'))) {
    throw 'Falta vpn/scripts/arrancar_servidores_seguro.sh.'
}

# Forzar UTF-8 para los caracteres especiales que puedan formar parte de la contraseña.
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$secure = $null
$bstr = [IntPtr]::Zero
$plano = $null
try {
    $cifrado = [System.IO.File]::ReadAllText($archivoPrivado, [System.Text.Encoding]::ASCII).Trim()
    $secure = ConvertTo-SecureString -String $cifrado
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plano = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    Write-Host 'Iniciando servidor BYODSEC en tu Ubuntu WSL2...' -ForegroundColor Cyan
    Write-Host 'Puertos: Access Server 943 | BYODSEC 9443 | RF1 8444'
    Write-Host 'Deja esta ventana abierta mientras uses BYODSEC. Para salir: Ctrl+C.'
    Push-Location $raiz
    try {
        # PowerShell envia solo el valor por stdin. NUNCA lo enviamos como parametro.
        $plano | & wsl.exe --exec bash ./vpn/scripts/arrancar_servidores_seguro.sh
        $codigo = $LASTEXITCODE
    }
    finally { Pop-Location }
    if ($codigo -ne 0) { throw "Error al arrancar WSL/BYODSEC (codigo $codigo)." }
}
finally {
    if ($bstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    if ($secure -ne $null) { $secure.Dispose() }
    $plano = $null
}
