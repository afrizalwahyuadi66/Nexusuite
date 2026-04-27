param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$NexusArgs
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Error "WSL belum terpasang. Install dulu: wsl --install -d Ubuntu"
    exit 1
}

$repoWinPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoWinPathUnix = ($repoWinPath -replace "\\", "/")
$repoWslPath = (& wsl.exe wslpath -a $repoWinPathUnix).Trim()

if (-not $repoWslPath) {
    Write-Error "Gagal mengonversi path project ke path WSL."
    exit 1
}

$escapedArgs = @()
foreach ($arg in $NexusArgs) {
    $escapedArgs += "'" + ($arg -replace "'", "'\"'\"'") + "'"
}
$argsLine = ($escapedArgs -join " ")

$cmd = "cd '$repoWslPath' && chmod +x nexusuite.sh && ./nexusuite.sh $argsLine"

Write-Host "[INFO] Menjalankan Nexusuite lewat WSL..."
Write-Host "[INFO] Path: $repoWslPath"
& wsl.exe bash -lc $cmd
exit $LASTEXITCODE
