@echo off
chcp 65001 >nul
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo waiting....
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
:: ═══════════════════════════════════════════════════════════════════════════
:: TorVPN — Windows Launcher
:: Run as Administrator (right-click → "Run as administrator")
:: ═══════════════════════════════════════════════════════════════════════════
setlocal EnableDelayedExpansion

echo.
echo  ████████╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ███╗   ██╗
echo     ██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║
echo     ██║   ██║   ██║██████╔╝██║   ██║██████╔╝██╔██╗ ██║
echo     ██║   ██║   ██║██╔══██╗╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
echo     ██║   ╚██████╔╝██║  ██║ ╚████╔╝ ██║     ██║ ╚████║
echo     ╚═╝    ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝
echo.
echo  Transparent Tor VPN — https://github.com/KHOSROW-II/torVPN//
echo.

:: ── Check Administrator ──────────────────────────────────────────────────
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo         Right-click the script and choose "Run as administrator".
    pause
    exit /b 1
)
echo [OK] Running as Administrator

:: ── Check dependencies ────────────────────────────────────────────────────
echo [CHECK] Verifying dependencies...

where tor.exe >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] tor.exe not found in PATH.
    echo         Download Tor Expert Bundle: https://www.torproject.org/download/tor/
    echo         Extract and add the directory containing tor.exe to your PATH,
    echo         or place tor.exe in the same directory as this script.
    pause
    exit /b 1
)
echo [OK] tor.exe found

if not exist "wintun.dll" (
    echo [ERROR] wintun.dll not found in current directory.
    echo         Download WinTUN: https://www.wintun.net/
    echo         Place wintun.dll next to this script.
    pause
    exit /b 1
)
echo [OK] wintun.dll found

where go.exe >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARN] go.exe not found — will try running pre-built torvpn.exe
    goto :run_binary
)
echo [OK] go.exe found

:: ── Build ─────────────────────────────────────────────────────────────────
echo.
echo [BUILD] Building torvpn.exe...
go build -ldflags="-s -w" -buildvcs=false -o torvpn.exe ./cmd/torvpn/
if %errorLevel% neq 0 (
    echo [ERROR] Build failed. Run: go build ./cmd/torvpn/ for details.
    pause
    exit /b 1
)
echo [OK] Build successful

:run_binary
:: ── Pre-flight: ensure DataDirectory exists ───────────────────────────────
if not exist "%TEMP%\tor-data" mkdir "%TEMP%\tor-data"

:: ── Run ───────────────────────────────────────────────────────────────────
echo.
echo [START] Launching TorVPN...
echo         Press Ctrl+C or close this window to stop.
echo.

torvpn.exe ^
    -torrc configs\torrc ^
    -tun torvpn0 ^
    -ip 10.0.0.1/24 ^
    -dns 127.0.0.1:5300 ^
    -socks-port 9050 ^
    -control-port 9051 ^
    -rotate 600 ^
    -verbose

echo.
echo [STOP] TorVPN exited (code %errorLevel%).
pause
