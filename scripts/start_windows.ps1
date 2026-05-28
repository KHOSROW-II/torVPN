#!/usr/bin/env pwsh
# ═══════════════════════════════════════════════════════════════════════════
# TorVPN — PowerShell Launcher (Windows)
# Usage: .\scripts\start_windows.ps1
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1

# ── Self-elevate if not already running as Administrator ──────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[TorVPN] Restarting as Administrator..." -ForegroundColor Yellow
    Start-Process pwsh -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ── Banner ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host " ████████╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ███╗   ██╗" -ForegroundColor Cyan
Write-Host "    ██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║" -ForegroundColor Cyan
Write-Host "    ██║   ██║   ██║██████╔╝██║   ██║██████╔╝██╔██╗ ██║" -ForegroundColor Cyan
Write-Host "    ██║   ██║   ██║██╔══██╗╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║" -ForegroundColor Cyan
Write-Host "    ██║   ╚██████╔╝██║  ██║ ╚████╔╝ ██║     ██║ ╚████║" -ForegroundColor Cyan
Write-Host "    ╚═╝    ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝" -ForegroundColor Cyan
Write-Host ""
Write-Host " Transparent Tor VPN — Route all traffic through Tor" -ForegroundColor White
Write-Host ""

# ── Switch to repo root ────────────────────────────────────────────────────
$scriptDir = Split-Path -Parent $PSCommandPath
Set-Location (Split-Path -Parent $scriptDir)

# ── Dependency checks ──────────────────────────────────────────────────────
function Check-Dependency {
    param([string]$Name, [string]$DownloadURL, [bool]$IsFile = $false)
    if ($IsFile) {
        if (-not (Test-Path $Name)) {
            Write-Host "[ERROR] $Name not found." -ForegroundColor Red
            Write-Host "        Download from: $DownloadURL" -ForegroundColor Yellow
            exit 1
        }
    } else {
        if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
            Write-Host "[ERROR] $Name not found in PATH." -ForegroundColor Red
            Write-Host "        Download from: $DownloadURL" -ForegroundColor Yellow
            exit 1
        }
    }
    Write-Host "[OK] $Name" -ForegroundColor Green
}

Write-Host "[CHECK] Verifying dependencies..." -ForegroundColor White
Check-Dependency "tor.exe"     "https://www.torproject.org/download/tor/"
Check-Dependency "wintun.dll"  "https://www.wintun.net/" -IsFile $true
Check-Dependency "go.exe"      "https://go.dev/dl/"

# ── Build ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[BUILD] Building torvpn.exe..." -ForegroundColor White
$env:GOFLAGS = "-trimpath"
& go build -ldflags="-s -w" -o torvpn.exe ./cmd/torvpn/
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Build failed." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] torvpn.exe built successfully" -ForegroundColor Green

# ── Ensure Tor DataDirectory exists ───────────────────────────────────────
$torData = "$env:TEMP\tor-data"
if (-not (Test-Path $torData)) { New-Item -ItemType Directory -Path $torData | Out-Null }

# ── Launch ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[START] Launching TorVPN... (Ctrl+C to stop)" -ForegroundColor Green
Write-Host ""

$params = @(
    "-torrc",         "configs\torrc",
    "-tun",           "torvpn0",
    "-ip",            "10.0.0.1/24",
    "-dns",           "127.0.0.1:5300",
    "-socks-port",    "9050",
    "-control-port",  "9051",
    "-control-pass",  "torvpnpass",
    "-rotate",        "600",
    "-verbose"
)

try {
    & .\torvpn.exe @params
} finally {
    Write-Host ""
    Write-Host "[STOP] TorVPN stopped." -ForegroundColor Yellow
}
