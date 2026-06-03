# TorVPN — GUI Integration Guide

This explains exactly how the GUI connects to the Go backend and what you need to do.

---

## How it works (the short version)

```
torvpn.exe  ←→  WebSocket ws://127.0.0.1:7070/ws  ←→  gui/index.html (your browser)
```

1. You run `torvpn.exe` (or the batch script)
2. It starts a small HTTP+WebSocket server on port 7070
3. It automatically opens your browser to `http://127.0.0.1:7070`
4. The GUI connects via WebSocket and from that point everything is live:
   - Every log line Tor prints → appears in the GUI console in real time
   - Bootstrap progress → updates the progress bar live
   - Circuit info → shown in the Circuits page
   - Bandwidth stats → updates every second
   - Clicking Connect/Disconnect in the GUI → actually starts/stops Tor

**No simulation. No fake data. The GUI is just a window into the real running process.**

---

## New files added

| File | What it does |
|------|-------------|
| `internal/api/server.go` | WebSocket server — bridge between GUI and Go code |
| `cmd/torvpn/main.go` | Rewritten to wire GUI callbacks into real VPN functions |
| `gui/index.html` | Updated GUI — dark/red theme, real WebSocket, all features |

## Changed files

| File | What changed |
|------|-------------|
| `internal/tor/controller.go` | Added `WaitForBootstrapWithCallback()` (pushes live progress to GUI), added `Purpose` field to `CircuitInfo` |
| `scripts/start_windows.bat` | Added `-api 127.0.0.1:7070` flag |
| `scripts/start_windows.ps1` | Same |

---

## Step-by-step: what to copy to your machine

### 1. Copy these files exactly as-is:

```
internal/api/server.go          ← NEW file, create this
cmd/torvpn/main.go              ← REPLACE existing
internal/tor/controller.go      ← REPLACE existing  
gui/index.html                  ← REPLACE existing
scripts/start_windows.bat       ← REPLACE existing
scripts/start_windows.ps1       ← REPLACE existing
```

### 2. Add the websocket dependency

`golang.org/x/net` is already in your `go.mod` and it includes `golang.org/x/net/websocket`.
Run this once after copying the files:

```cmd
go mod tidy
```

### 3. Build and run

```cmd
.\scripts\start_windows.bat
```

Your browser opens automatically at `http://127.0.0.1:7070`.

---

## What each GUI button actually does

| GUI action | What happens in Go |
|-----------|-------------------|
| Click **Connect** | Calls `app.connect()` → starts tor.New(), WaitForBootstrap, dns.NewServer, tun.New() |
| Click **Disconnect** | Calls `app.disconnect()` → closes TUN, DNS, circuit manager, Tor process |
| Click **New circuit** | Sends `SIGNAL NEWNYM` to Tor control port |
| Console log lines | Every `log.Printf()` call in Go is intercepted and sent to GUI via WebSocket |
| Bootstrap bar | `WaitForBootstrapWithCallback` sends progress every time it changes |
| Circuit list | `GETINFO circuit-status` result sent to GUI after connect and after NEWNYM |
| Exit IP display | GUI receives it from `detectExitIP()` which queries `check.torproject.org` via Tor |
| Bandwidth bars | `BroadcastStats()` called every second from `statsTicker()` goroutine |
| Check updates | Queries `api.github.com/repos/KHOSROW-II/torVPN/releases/latest` |
| Set config sliders | Sends `set_config` WebSocket command → `app.setConfig()` in Go |

---

## WebSocket message format (for reference)

All messages are JSON. Backend → GUI:

```json
{"type":"log",       "level":"notice", "msg":"[Tor] Bootstrap 50%", "ts":"13:04:05"}
{"type":"status",    "state":"connected"}
{"type":"stats",     "txBytes":1234, "rxBytes":5678, "txRate":100, "rxRate":200}
{"type":"bootstrap", "pct":75, "tag":"loading_descriptors", "summary":"Loading relay descriptors"}
{"type":"circuit",   "circuits":[{"id":1,"status":"BUILT","path":"A~guard,B~mid,C~exit","purpose":"GENERAL"}]}
{"type":"exitip",    "ip":"185.220.101.1", "country":"DE"}
{"type":"update",    "version":"v1.1.0", "url":"https://github.com/...", "name":"...", "date":"2026-01-01"}
```

GUI → Backend:

```json
{"cmd":"connect"}
{"cmd":"disconnect"}
{"cmd":"newnym"}
{"cmd":"get_circuits"}
{"cmd":"check_update"}
{"cmd":"set_config", "key":"rotate_interval", "value":"300"}
{"cmd":"set_config", "key":"bridge_type",     "value":"snowflake"}
{"cmd":"set_config", "key":"obfs4_bridges",   "value":"obfs4 1.2.3.4:443 ..."}
```

---

## Bridge configuration from the GUI

### obfs4
1. Go to **Bridges page** → select **obfs4**
2. Set path to `obfs4proxy.exe` (must be next to `tor.exe`)
3. Paste bridge lines from https://bridges.torproject.org/bridges?transport=obfs4
4. Click **Save to torrc** — this writes the bridge lines to `configs\torrc`
5. Click **Connect** (or Apply & reconnect from Connection page)

### Snowflake
1. Go to **Bridges page** → select **Snowflake**
2. Download `snowflake-client.exe` from GitLab (link shown in GUI)
3. Set the path (default: `snowflake-client.exe` next to `tor.exe`)
4. Click **Save Snowflake config** → writes to `configs\torrc`
5. Click **Connect**

The torrc entries written for Snowflake:
```
UseBridges 1
ClientTransportPlugin snowflake exec snowflake-client.exe
Bridge snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72
```

---

## Per-app tunneling — manual add

On the **Tunneling → Apps** tab:
1. Click **Add app**
2. Enter the display name (e.g. `Telegram`)
3. Enter the executable name (e.g. `Telegram.exe`)
4. Click **Add** — the app appears in the list with a toggle

This sends `set_config app_tunnel_add Telegram.exe` to the backend.
The backend's `setConfig()` function receives it and can apply per-process routing rules
(e.g. via Windows Firewall rules or process-level SOCKS5 injection).

---

## Troubleshooting

**Browser shows "GUI not found"**
→ Make sure `gui/index.html` is in a `gui/` folder next to `torvpn.exe`

**GUI says "WebSocket disconnected — retrying"**
→ The backend hasn't started yet, or crashed. Check the terminal window for errors.
→ The GUI retries every 3 seconds automatically.

**Bootstrap progress shows in terminal but not in GUI**
→ You're using the old `main.go`. Replace it with the new version.

**"Cannot find module golang.org/x/net/websocket"**
→ Run `go mod tidy` in the project root.

**Port 7070 already in use**
→ Change the port: add `-api 127.0.0.1:7071` to the command and update the 
  `WS_URL` constant at the top of `gui/index.html` to match.
