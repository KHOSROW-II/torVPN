#!/usr/bin/env pwsh
#Requires -Version 5.1

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process pwsh -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$scriptDir = Split-Path -Parent $PSCommandPath
Set-Location (Split-Path -Parent $scriptDir)

Write-Host ""
Write-Host " TorVPN — Starting up..." -ForegroundColor Red
Write-Host ""

function Check-Dep($Name, $URL, $IsFile=$false) {
    if ($IsFile) { if (-not (Test-Path $Name)) { Write-Host "[ERROR] $Name missing. Get it from: $URL" -ForegroundColor Red; exit 1 } }
    else { if (-not (Get-Command $Name -EA SilentlyContinue)) { Write-Host "[ERROR] $Name not in PATH. $URL" -ForegroundColor Red; exit 1 } }
    Write-Host "[OK] $Name" -ForegroundColor Green
}

Check-Dep "tor.exe"    "https://www.torproject.org/download/tor/"
Check-Dep "wintun.dll" "https://www.wintun.net/" -IsFile $true
Check-Dep "go.exe"     "https://go.dev/dl/"

Write-Host "[BUILD] Building..." -ForegroundColor White
& go build -ldflags="-s -w" -buildvcs=false -o torvpn.exe ./cmd/torvpn/
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Build failed." -ForegroundColor Red; exit 1 }
Write-Host "[OK] Built" -ForegroundColor Green

if (-not (Test-Path "tor-data")) { New-Item -ItemType Directory -Path "tor-data" | Out-Null }

Write-Host ""
Write-Host "[START] Launching TorVPN GUI at http://127.0.0.1:7070" -ForegroundColor Green
Write-Host "        Your browser will open automatically." -ForegroundColor White
Write-Host ""

try {
    & .\torvpn.exe -torrc configs\torrc -tun torvpn0 -ip 10.0.0.1/24 `
        -dns 127.0.0.1:5300 -socks-port 9050 -control-port 9051 `
        -rotate 600 -api 127.0.0.1:7070 -verbose
} finally {
    Write-Host "[STOP] TorVPN stopped." -ForegroundColor Yellow
}
