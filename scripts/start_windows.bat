@echo off
chcp 65001 >nul
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo waiting....
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
setlocal EnableDelayedExpansion

echo.
echo  ████████╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ███╗   ██╗
echo     ██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║
echo     ██║   ██║   ██║██████╔╝██║   ██║██████╔╝██╔██╗ ██║
echo     ██║   ██║   ██║██╔══██╗╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
echo     ██║   ╚██████╔╝██║  ██║ ╚████╔╝ ██║     ██║ ╚████║
echo     ╚═╝    ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝
echo.
echo  Transparent Tor VPN with GUI — https://github.com/KHOSROW-II/torVPN
echo.

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Must run as Administrator.
    echo         Right-click and choose "Run as administrator".
    pause & exit /b 1
)
echo [OK] Running as Administrator

:: Dependencies
where tor.exe >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] tor.exe not found in PATH.
    echo         Download Tor Expert Bundle: https://www.torproject.org/download/tor/
    pause & exit /b 1
)
echo [OK] tor.exe found

if not exist "wintun.dll" (
    echo [ERROR] wintun.dll not found.
    echo         Download WinTUN: https://www.wintun.net/
    pause & exit /b 1
)
echo [OK] wintun.dll found

where go.exe >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARN] go.exe not found — trying pre-built torvpn.exe
    goto :run
)
echo [OK] go.exe found

:: Build
echo.
echo [BUILD] Building torvpn.exe...
go build -ldflags="-s -w" -buildvcs=false -o torvpn.exe ./cmd/torvpn/
if %errorLevel% neq 0 (
    echo [ERROR] Build failed.
    pause & exit /b 1
)
echo [OK] Build successful

:run
if not exist "tor-data" mkdir "tor-data"

echo.
echo [START] Launching TorVPN...
echo         GUI will open at: http://127.0.0.1:7070
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
    -api 127.0.0.1:7070 ^
    -verbose

echo.
echo [STOP] TorVPN exited (code %errorLevel%).
pause
