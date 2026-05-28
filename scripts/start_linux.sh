#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# TorVPN — Linux Launcher
# Usage: sudo ./scripts/start_linux.sh
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Banner ────────────────────────────────────────────────────────────────
echo -e "${CYAN}"
echo " ████████╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ███╗   ██╗"
echo "    ██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║"
echo "    ██║   ██║   ██║██████╔╝██║   ██║██████╔╝██╔██╗ ██║"
echo "    ██║   ██║   ██║██╔══██╗╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║"
echo "    ██║   ╚██████╔╝██║  ██║ ╚████╔╝ ██║     ██║ ╚████║"
echo "    ╚═╝    ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝"
echo -e "${RESET}"
echo -e "${BOLD} Transparent Tor VPN — Route all traffic through Tor${RESET}"
echo

# ── Check root ────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must run as root.${RESET}"
    echo "        Re-run with: sudo $0"
    exit 1
fi
echo -e "${GREEN}[OK]${RESET} Running as root"

# ── Switch to repo root ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

# ── Check dependencies ────────────────────────────────────────────────────
check_dep() {
    local name="$1"; local install="$2"
    if ! command -v "$name" &>/dev/null; then
        echo -e "${RED}[ERROR]${RESET} $name not found."
        echo "        Install with: $install"
        exit 1
    fi
    echo -e "${GREEN}[OK]${RESET} $name"
}

echo "[CHECK] Verifying dependencies..."
check_dep "tor"    "apt install tor  /  dnf install tor  /  pacman -S tor"
check_dep "go"     "https://go.dev/dl/ or apt install golang-go"
check_dep "ip"     "apt install iproute2"

# Check TUN device
if [[ ! -c /dev/net/tun ]]; then
    echo -e "${YELLOW}[WARN]${RESET} /dev/net/tun not found — loading tun module..."
    modprobe tun || { echo -e "${RED}[ERROR]${RESET} Cannot load tun module"; exit 1; }
fi
echo -e "${GREEN}[OK]${RESET} /dev/net/tun"

# ── Build ─────────────────────────────────────────────────────────────────
echo
echo "[BUILD] Building torvpn..."
GOFLAGS="-trimpath" go build -ldflags="-s -w" -o torvpn ./cmd/torvpn/
echo -e "${GREEN}[OK]${RESET} ./torvpn built"

# ── Pre-flight: Tor data directory ────────────────────────────────────────
mkdir -p /tmp/tor-data
chmod 700 /tmp/tor-data

# ── Set up DNS redirect (redirect system DNS queries to our resolver) ──────
# We update /etc/resolv.conf to point at our local DoH proxy.
# A backup is saved to /etc/resolv.conf.torvpn.bak and restored on exit.

DNS_BACKUP="/etc/resolv.conf.torvpn.bak"
if [[ ! -f "$DNS_BACKUP" ]]; then
    cp /etc/resolv.conf "$DNS_BACKUP"
    echo -e "${GREEN}[OK]${RESET} Backed up /etc/resolv.conf → $DNS_BACKUP"
fi

echo "# TorVPN DNS — managed automatically. Do not edit." > /etc/resolv.conf
echo "nameserver 127.0.0.1" >> /etc/resolv.conf
echo -e "${GREEN}[OK]${RESET} DNS redirected to 127.0.0.1"

# ── Cleanup on exit ───────────────────────────────────────────────────────
cleanup() {
    echo
    echo -e "${YELLOW}[STOP]${RESET} TorVPN stopped. Restoring DNS..."
    if [[ -f "$DNS_BACKUP" ]]; then
        cp "$DNS_BACKUP" /etc/resolv.conf
        rm -f "$DNS_BACKUP"
        echo -e "${GREEN}[OK]${RESET} /etc/resolv.conf restored"
    fi
    # Routes are removed by torvpn itself via defer; also clean up here as fallback
    ip route del 0.0.0.0/1 dev torvpn0 2>/dev/null || true
    ip route del 128.0.0.0/1 dev torvpn0 2>/dev/null || true
    echo "[DONE] Cleanup complete."
}
trap cleanup EXIT INT TERM

# ── Launch ────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}[START]${RESET} Launching TorVPN... (Ctrl+C to stop)"
echo

./torvpn \
    -torrc configs/torrc \
    -tun torvpn0 \
    -ip 10.0.0.1/24 \
    -dns 127.0.0.1:5300 \
    -socks-port 9050 \
    -control-port 9051 \
    -control-pass torvpnpass \
    -rotate 600 \
    -verbose
