# TorVPN

**A transparent VPN that routes all system traffic through the Tor network.**  
Implemented in Go — designed for Windows first, Linux-compatible with no code changes.

```
  ┌─────────────┐     ┌──────────────┐    ┌──────────────┐     ┌──────────────┐
  │  Your app   │───▶│  TUN device  │───▶│  Tor SOCKS5  │───▶│  Tor Network │
  │  (any OS)   │     │  torvpn      │    │  127.0.0.1   │     │  → Internet  │
  └─────────────┘     └──────────────┘    │  :9050       │     └──────────────┘
                                          └──────────────┘
                          ▲
                     ┌────┴────────┐
                     │ DoH Resolver│  ← All DNS goes here (no leaks)
                     │ 127.0.0.1   │    then through Tor to 1.1.1.1
                     │ :5300       │
                     └─────────────┘
```

---

## Contents

1. [Architecture](#architecture)  
2. [Prerequisites — Windows](#prerequisites--windows)  
3. [Prerequisites — Linux](#prerequisites--linux)  
4. [Building](#building)  
5. [Running on Windows](#running-on-windows)  
6. [Running on Linux](#running-on-linux)  
7. [Docker (Linux)](#docker)  
8. [Speed Tuning & torrc](#speed-tuning--torrc)  
9. [Using Bridges (obfs4)](#using-bridges-obfs4)  
10. [Troubleshooting](#troubleshooting)  
11. [Security Notes](#security-notes)  
12. [Project Structure](#project-structure)

---

## Architecture

| Component | File | Responsibility |
|-----------|------|----------------|
| **Main** | `cmd/torvpn/main.go` | Wires all components together, signal handling |
| **Tor Controller** | `internal/tor/controller.go` | Spawns Tor, monitors bootstrap, sends NEWNYM |
| **Circuit Manager** | `internal/circuit/manager.go` | Periodic rotation, relay scoring by bandwidth |
| **DNS Resolver** | `internal/dns/server.go` | Leak-proof DNS via DoH through Tor |
| **TUN Device** | `internal/tun/device.go` | Packet I/O, SOCKS5 forwarding |
| **Windows TUN shim** | `internal/tun/tun_windows.go` | `netsh`, WinTUN wiring |
| **Linux TUN shim** | `internal/tun/tun_linux.go` | `ip addr/route`, kernel TUN |

### Traffic routing

```
DNS query (UDP/53)
  → TUN → redirected to 127.0.0.1:5300
  → DoH (HTTPS) → Tor SOCKS5 → 1.1.1.1 → answer

TCP connection
  → TUN → SOCKS5 dial through Tor → remote server

UDP (non-DNS)
  → TUN → best-effort SOCKS5 forwarding (most Tor exits are TCP only)

ICMP
  → dropped (Tor cannot carry ICMP)
```

---

## Prerequisites — Windows

### 1. Go (1.22+)

Download from https://go.dev/dl/ and install.  
Verify: `go version`

### 2. Tor Expert Bundle

1. Download **Tor Expert Bundle** from https://www.torproject.org/download/tor/  
2. Extract the ZIP.  
3. Add the extracted folder to your system `PATH`:  
   - Open **Environment Variables → New**  
   - Add the full path (e.g. `\tor\`)  
4. Verify: `tor.exe --version`

### 3. WinTUN driver

1. Download `wintun-x86_64-*.zip` from https://www.wintun.net/  
2. Extract `wintun.dll` (64-bit version) into the **same directory** as `torvpn.exe`  
   (or into a folder in your `PATH`).

> WinTUN is the same driver WireGuard uses on Windows — it is stable and well-maintained.

### 4. Visual C++ Redistributable (usually already installed)

Required for `wintun.dll`. Download from Microsoft if you see DLL errors.

---

## Prerequisites — Linux

### Debian/Ubuntu

```bash
sudo apt update
sudo apt install -y tor iproute2 golang-go
# For obfs4 bridges (optional):
sudo apt install -y obfs4proxy
```

### Fedora/RHEL

```bash
sudo dnf install -y tor iproute golang
```

### Arch Linux

```bash
sudo pacman -S tor iproute2 go
```

### Manual Go install (recommended for latest Go)

```bash
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
go version
```

### TUN kernel module

```bash
# Check if already loaded
ls /dev/net/tun

# If missing, load it:
sudo modprobe tun

# Make it load at boot:
echo "tun" | sudo tee /etc/modules-load.d/tun.conf
```

---

## Building

Clone and build from either OS:

```bash
# Clone
https://github.com/KHOSROW-II/torVPN.git
cd torvpn

# Download Go dependencies
go mod tidy

# Build for current OS
go build -ldflags="-s -w" -o torvpn ./cmd/torvpn/
# Windows: produces torvpn.exe
# Linux:   produces ./torvpn

# Cross-compile from Linux → Windows:
GOOS=windows GOARCH=amd64 go build -o torvpn.exe ./cmd/torvpn/

# Cross-compile from Windows → Linux (in PowerShell):
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o torvpn ./cmd/torvpn/
```

---

## Running on Windows

```powershell
# Option A: PowerShell script (auto-elevates, checks deps, builds & runs)
.\scripts\start_windows.ps1

# Option B: Batch file
.\scripts\start_windows.bat

# Option C: Manual (from an Administrator terminal)
go run ./cmd/torvpn/ -verbose
```

> **Must be run as Administrator.** WinTUN requires Administrator to create the virtual network adapter.

On first run, Windows Firewall may ask to allow `torvpn.exe` — click **Allow access**.

### Verify it's working (Windows)

```powershell
# Check your exit IP — should be a Tor exit node
Invoke-WebRequest -Uri "https://check.torproject.org/api/ip" | Select-Object -ExpandProperty Content

# Check for DNS leaks
Invoke-WebRequest -Uri "https://dnsleaktest.com" -UseBasicParsing
```

---

## Running on Linux

```bash
# Make script executable (once)
chmod +x scripts/start_linux.sh

# Run as root
sudo ./scripts/start_linux.sh

# Or manually:
sudo ./torvpn -torrc configs/torrc -tun torvpn0 -ip 10.0.0.1/24 \
              -dns 127.0.0.1:5300 -socks-port 9050 -verbose
```

The Linux script automatically:
- Backs up `/etc/resolv.conf` and points DNS at `127.0.0.1`
- Restores `/etc/resolv.conf` on Ctrl+C / exit
- Loads the `tun` kernel module if needed

### Verify it's working (Linux)

```bash
# Check your exit IP
curl https://check.torproject.org/api/ip

# Full DNS leak test
curl https://ipleak.net/json/

# Confirm traffic is going through TUN
ip route show | grep torvpn0
```

---

## Docker

```bash
# Build image
docker build -t torvpn .

# Run (requires TUN device and NET_ADMIN)
docker run --rm \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  -p 9050:9050 \
  torvpn

# With custom torrc mounted in
docker run --rm \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  -v $(pwd)/configs/torrc:/etc/torvpn/torrc:ro \
  torvpn
```

---

## Speed Tuning & torrc

Tor is inherently slower than a regular VPN due to 3-hop onion routing. These tunings minimize unnecessary latency:

### Key parameters in `configs/torrc`

| Parameter | Default | Effect |
|-----------|---------|--------|
| `CircuitBuildTimeout` | `10` | Give up on slow circuit builds faster |
| `NewCircuitPeriod` | `30` | Build spare circuits proactively |
| `MaxCircuitDirtiness` | `600` | Rotate after 10 min (balance freshness/overhead) |
| `MaxClientCircuitsPending` | `16` | More parallel build attempts |
| `NumEntryGuards` | `3` | More guard diversity |
| `KeepalivePeriod` | `60` | Prevent NAT expiry on idle |

### Relay selection

Tor automatically selects relays weighted by bandwidth. The `circuit.Manager` in TorVPN additionally:
- Fetches relay data from the Onionoo API
- Scores relays: `bandwidth × stability_multiplier`
- Logs the top relays for observability

You can bias selection further with `torrc`:

```
# Prefer relays in specific countries (faster for your region)
EntryNodes {DE},{NL},{CH}
StrictNodes 0   # 0 = fall back if unavailable; 1 = strict

# Exclude known-slow or unreliable exits
ExcludeExitNodes {RU},{CN},{IR}
```

### Latency benchmarking

```bash
# Linux: measure time to get a response via TorVPN
time curl -s https://check.torproject.org/api/ip

# Compare without TorVPN (stop it first)
time curl -s https://api.ipify.org
```

Typical Tor latency: 300–600ms additional per hop. HTTP/2 and connection keep-alive significantly help.

---

## Using Bridges (obfs4)

If your ISP throttles or blocks Tor, use **obfs4 bridges**:

### 1. Install obfs4proxy

```bash
# Debian/Ubuntu
sudo apt install obfs4proxy

# Windows: download obfs4proxy.exe from
# https://github.com/Yawning/obfs4/releases
# Place next to tor.exe
```

### 2. Get bridge lines

Visit https://bridges.torproject.org/ → select **obfs4** → get lines like:

```
obfs4 192.0.2.1:443 FINGERPRINT cert=XXXX iat-mode=0
```

### 3. Enable in torrc

```
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 192.0.2.1:443 FINGERPRINT cert=XXXX iat-mode=0
Bridge obfs4 192.0.2.2:8080 FINGERPRINT cert=YYYY iat-mode=0
```

> You need at least 2 bridge lines for reliability.

---

## Troubleshooting

### `[TUN] Failed to create TUN: ...`

**Windows:**
- Ensure `wintun.dll` is next to `torvpn.exe`
- Run as Administrator
- Check Windows Event Viewer for driver errors
- Reinstall WinTUN if needed: https://www.wintun.net/

**Linux:**
```bash
sudo modprobe tun
ls -la /dev/net/tun          # should show crw-rw-rw-
sudo setcap cap_net_admin+eip ./torvpn   # alternative to running as root
```

### `[Tor] bootstrap timed out`

- Tor can take 2–3 minutes on a slow connection — increase `-torrc` timeout
- Check if Tor is blocked by your firewall: `telnet 5.9.158.75 9001`
- Enable obfs4 bridges (see above)
- Check your `configs/torrc` for syntax errors: `tor -f configs/torrc --verify-config`

### `[Tor] Failed to start: ... is Tor installed?`

- **Windows:** Ensure `tor.exe` is in PATH or in the current directory
- **Linux:** `which tor` should return a path; install if missing
- Test manually: `tor -f configs/torrc`

### DNS leaks detected

1. Verify TorVPN's DNS resolver is running: `nc -u 127.0.0.1 5300` (send a query)
2. On Linux, check `/etc/resolv.conf` points to `127.0.0.1`
3. On Windows, verify the adapter's DNS is set to `127.0.0.1`
4. Check for `systemd-resolved` overriding DNS:
   ```bash
   sudo systemctl stop systemd-resolved
   ```

### High memory usage from relay data

The Onionoo relay fetch downloads ~1 MB of data every 30 minutes. To disable:

Set `FetchUselessDescriptors 0` in torrc (already the default) and reduce relay refresh in `circuit/manager.go`:

```go
relayTicker := time.NewTicker(4 * time.Hour)  // was 30 minutes
```

### `netsh` errors on Windows

```
> netsh interface ip set address name="..." static ...
```

- Ensure you're running as Administrator
- The WinTUN adapter may not be visible until TorVPN has started once
- Check adapter name in Device Manager

### Routes not removed after crash

**Windows:**
```cmd
route delete 0.0.0.0 mask 128.0.0.0
route delete 128.0.0.0 mask 128.0.0.0
```

**Linux:**
```bash
sudo ip route del 0.0.0.0/1 dev torvpn0
sudo ip route del 128.0.0.0/1 dev torvpn0
sudo ip rule del fwmark 0x1 lookup main
```

### Circuit rotation not working

Check the control password matches in both `torrc` (HashedControlPassword) and the flag (`-control-pass`). Regenerate the hash:

```bash
tor --hash-password "yournewpassword"
# Copy the output (16:...) into HashedControlPassword in torrc
```

---

## Security Notes

- **This software does not provide anonymity on its own.** Application-level identifiers (cookies, logged-in accounts, WebRTC, etc.) can still de-anonymize you.
- The `HashedControlPassword` in the default `torrc` is public. **Change it** before using TorVPN on a shared or production system.
- Tor's SOCKS5 proxy (`127.0.0.1:9050`) is bound to localhost only and not exposed to the network.
- The DNS resolver (`127.0.0.1:5300`) is also localhost-only.
- UDP (non-DNS) traffic has limited Tor support. Most Tor exits are TCP-only. UDP will either be dropped or carried via TCP tunnelling with overhead.
- ICMP (ping) is always dropped — this is expected behaviour.

---

## Project Structure

```
torvpn/
├── cmd/
│   └── torvpn/
│       └── main.go              ← Entry point, flag parsing, wiring
├── internal/
│   ├── circuit/
│   │   └── manager.go           ← Circuit rotation, relay scoring
│   ├── dns/
│   │   └── server.go            ← Leak-proof DoH resolver
│   ├── tor/
│   │   └── controller.go        ← process, connects to its control port, polls bootstrap progress
│   └── tun/
│       ├── device.go            ← TUN I/O, packet forwarding
│       ├── tun_windows.go       ← Windows: WinTUN, netsh (build tag: windows)
│       └── tun_linux.go         ← Linux: /dev/net/tun, ip (build tag: linux)
├── configs/
│   └── torrc                    ← Performance-tuned torrc (auto-generated if absent)
├── scripts/
│   ├── start_windows.bat        ← Windows batch launcher
│   ├── start_windows.ps1        ← Windows PowerShell launcher (auto-elevates)
│   └── start_linux.sh           ← Linux bash launcher (handles DNS + cleanup)
├── Dockerfile                   ← Multi-stage Linux container
├── go.mod
└── README.md
```

---

## License

MIT — see LICENSE file.
