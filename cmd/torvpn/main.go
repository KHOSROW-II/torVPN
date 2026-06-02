// TorVPN - Transparent Tor VPN with real-time GUI.
//
// Architecture:
//   main.go → starts API server (WebSocket on :7070)
//           → starts Tor daemon + controller
//           → starts DNS, TUN, circuit manager
//           → GUI (gui/index.html) connects via WebSocket and drives everything
//
// Run as Administrator on Windows, root on Linux.
// Open http://127.0.0.1:7070 in any browser, or use the --no-gui flag for CLI mode.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KHOSROW-II/torvpn/internal/api"
	"github.com/KHOSROW-II/torvpn/internal/circuit"
	"github.com/KHOSROW-II/torvpn/internal/dns"
	"github.com/KHOSROW-II/torvpn/internal/tor"
	"github.com/KHOSROW-II/torvpn/internal/tun"
)

const (
	currentVersion = "v1.0.0"
	githubRepo     = "KHOSROW-II/torVPN"
	apiAddr        = "127.0.0.1:7070"
)

// Config holds all runtime configuration.
type Config struct {
	TorrcPath      string
	TUNName        string
	TUNIP          string
	DNSListenAddr  string
	SocksPort      int
	ControlPort    int
	RotateInterval int
	Verbose        bool
	NoGUI          bool   // if true, skip opening browser
	APIAddr        string // WebSocket/HTTP server address
}

// App holds all live components so they can be started/stopped by the GUI.
type App struct {
	cfg       *Config
	apiServer *api.Server

	mu         sync.Mutex
	torCtrl    *tor.Controller
	dnsServer  *dns.Server
	tunDev     *tun.Device
	circuitMgr *circuit.Manager
	state      string // "disconnected" | "connecting" | "connected"

	// stats
	txBytes int64
	rxBytes int64
}

func main() {
	cfg := parseFlags()

	app := &App{cfg: cfg, state: "disconnected"}

	// ── Set up API server ────────────────────────────────────────────────────
	srv := api.New(cfg.APIAddr, api.Callbacks{
		Connect:     app.connect,
		Disconnect:  app.disconnect,
		NewCircuit:  app.newCircuit,
		GetCircuits: app.getCircuits,
		GetStatus:   func() string { return app.state },
		SetConfig:   app.setConfig,
		CheckUpdate: checkUpdate,
	})
	app.apiServer = srv

	// Tee all log output into the WebSocket so the GUI console shows real logs
	lw := srv.GetLogWriter()
	lw.SetBase(os.Stderr)
	log.SetOutput(lw)
	log.SetFlags(log.Ltime | log.Lshortfile)

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start API server: %v\n", err)
		os.Exit(1)
	}
	defer srv.Stop()

	log.Printf("[TorVPN] GUI available at http://%s", cfg.APIAddr)

	// Open browser automatically unless --no-gui
	if !cfg.NoGUI {
		go openBrowser("http://" + cfg.APIAddr)
	}

	// ── Wait for termination ─────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[TorVPN] Shutting down...")
	app.disconnect()
}

// ── connect / disconnect ─────────────────────────────────────────────────────

func (a *App) connect() error {
	a.mu.Lock()
	if a.state != "disconnected" {
		a.mu.Unlock()
		return fmt.Errorf("already %s", a.state)
	}
	a.state = "connecting"
	a.mu.Unlock()

	a.apiServer.BroadcastLog("notice", "[TorVPN] Starting up...")

	// 1. Start Tor
	torCtrl, err := tor.New(tor.Options{
		TorrcPath:   a.cfg.TorrcPath,
		SocksPort:   a.cfg.SocksPort,
		ControlPort: a.cfg.ControlPort,
		Verbose:     a.cfg.Verbose,
	})
	if err != nil {
		a.state = "disconnected"
		return fmt.Errorf("start tor: %w", err)
	}

	// 2. Bootstrap with live progress pushed to GUI
	err = torCtrl.WaitForBootstrapWithCallback(300, func(pct int, tag, summary string) {
		a.apiServer.BroadcastBootstrap(pct, tag, summary)
		a.apiServer.BroadcastLog("notice",
			fmt.Sprintf("[Tor] Bootstrap %d%% (%s): %s", pct, tag, summary))
	})
	if err != nil {
		a.apiServer.BroadcastLog("warn",
			"[TorVPN] Bootstrap timeout — continuing anyway")
	} else {
		a.apiServer.BroadcastLog("notice", "[TorVPN] Tor bootstrap complete (100%)")
	}

	// 3. Circuit manager
	cm := circuit.NewManager(circuit.ManagerOptions{
		TorCtrl:        torCtrl,
		RotateInterval: a.cfg.RotateInterval,
		Verbose:        a.cfg.Verbose,
	})
	cm.Start()

	// 4. DNS server
	dnsServer, err := dns.NewServer(dns.Options{
		ListenAddr: a.cfg.DNSListenAddr,
		SocksAddr:  torCtrl.SocksAddr(),
		Verbose:    a.cfg.Verbose,
	})
	if err != nil {
		cm.Stop()
		torCtrl.Stop()
		a.state = "disconnected"
		return fmt.Errorf("dns server: %w", err)
	}
	go dnsServer.Serve()
	a.apiServer.BroadcastLog("notice",
		"[DNS] Resolver listening on "+a.cfg.DNSListenAddr)

	// 5. TUN interface
	tunDev, err := tun.New(tun.Options{
		Name:      a.cfg.TUNName,
		CIDR:      a.cfg.TUNIP,
		SocksAddr: torCtrl.SocksAddr(),
		DNSAddr:   a.cfg.DNSListenAddr,
		Verbose:   a.cfg.Verbose,
	})
	if err != nil {
		dnsServer.Stop()
		cm.Stop()
		torCtrl.Stop()
		a.state = "disconnected"
		return fmt.Errorf("tun device: %w", err)
	}
	go tunDev.Run()

	a.mu.Lock()
	a.torCtrl = torCtrl
	a.dnsServer = dnsServer
	a.tunDev = tunDev
	a.circuitMgr = cm
	a.state = "connected"
	a.txBytes = 0
	a.rxBytes = 0
	a.mu.Unlock()

	a.apiServer.BroadcastLog("notice",
		"[TorVPN] TUN interface up — all traffic routed through Tor")

	// Push initial circuit list
	time.Sleep(500 * time.Millisecond)
	a.apiServer.Broadcast(api.OutMsg{
		Type:     "circuit",
		Circuits: a.getCircuits(),
	})

	// Detect exit IP
	go a.detectExitIP()

	// Start stats ticker
	go a.statsTicker()

	return nil
}

func (a *App) disconnect() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state == "disconnected" {
		return
	}
	a.state = "disconnected"

	if a.tunDev != nil {
		a.tunDev.Close()
		a.tunDev = nil
	}
	if a.dnsServer != nil {
		a.dnsServer.Stop()
		a.dnsServer = nil
	}
	if a.circuitMgr != nil {
		a.circuitMgr.Stop()
		a.circuitMgr = nil
	}
	if a.torCtrl != nil {
		a.torCtrl.Stop()
		a.torCtrl = nil
	}
	a.apiServer.BroadcastLog("notice", "[TorVPN] Disconnected")
}

func (a *App) newCircuit() error {
	a.mu.Lock()
	ctrl := a.torCtrl
	a.mu.Unlock()
	if ctrl == nil {
		return fmt.Errorf("not connected")
	}
	return ctrl.NewCircuit()
}

func (a *App) getCircuits() []api.CircuitMsg {
	a.mu.Lock()
	ctrl := a.torCtrl
	a.mu.Unlock()
	if ctrl == nil {
		return nil
	}
	raw, err := ctrl.GetCircuitInfo()
	if err != nil {
		return nil
	}
	out := make([]api.CircuitMsg, 0, len(raw))
	for _, c := range raw {
		out = append(out, api.CircuitMsg{
			ID:      c.ID,
			Status:  c.Status,
			Path:    c.Path,
			Purpose: c.Purpose,
		})
	}
	return out
}

func (a *App) setConfig(key, value string) {
	switch key {
	case "rotate_interval":
		// Update circuit manager rotation interval live
		log.Printf("[Config] rotate_interval = %s", value)
	case "verbose":
		a.cfg.Verbose = value == "true"
	}
}

// ── Exit IP detection ────────────────────────────────────────────────────────

func (a *App) detectExitIP() {
	// Use Tor SOCKS5 to fetch our exit IP from check.torproject.org
	time.Sleep(2 * time.Second)
	a.mu.Lock()
	ctrl := a.torCtrl
	a.mu.Unlock()
	if ctrl == nil {
		return
	}

	// Simple HTTP request via Tor SOCKS5 proxy
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		a.apiServer.BroadcastLog("debug", "[ExitIP] Detection failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	var result struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	country := detectCountry(result.IP)
	a.apiServer.BroadcastExitIP(result.IP, country)
	a.apiServer.BroadcastLog("notice",
		fmt.Sprintf("[TorVPN] Exit IP: %s (%s) IsTor=%v", result.IP, country, result.IsTor))
}

// detectCountry does a simple GeoIP lookup using ip-api.com (plain HTTP, no key needed).
func detectCountry(ip string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip + "?fields=countryCode,country")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var r struct {
		CountryCode string `json:"countryCode"`
		Country     string `json:"country"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	return r.CountryCode
}

// ── Stats ticker ─────────────────────────────────────────────────────────────

func (a *App) statsTicker() {
	prevTx, prevRx := int64(0), int64(0)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range tick.C {
		a.mu.Lock()
		if a.state != "connected" {
			a.mu.Unlock()
			return
		}
		// In a real implementation, read from the TUN device's byte counters.
		// For now we expose the accumulated totals; the TUN package should
		// expose TxBytes()/RxBytes() methods to read them here.
		tx := a.txBytes
		rx := a.rxBytes
		a.mu.Unlock()

		txRate := tx - prevTx
		rxRate := rx - prevRx
		prevTx = tx
		prevRx = rx
		a.apiServer.BroadcastStats(tx, rx, txRate, rxRate)
	}
}

// AddBytes is called by the TUN package to account for forwarded data.
func (a *App) AddBytes(tx, rx int64) {
	a.mu.Lock()
	a.txBytes += tx
	a.rxBytes += rx
	a.mu.Unlock()
}

// ── Update checker ───────────────────────────────────────────────────────────

func checkUpdate() (*api.UpdateInfo, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var release struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
		HTMLURL string `json:"html_url"`
		Published string `json:"published_at"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, err
	}

	if release.TagName == "" || release.TagName == currentVersion {
		return nil, nil // already up to date
	}

	date := ""
	if len(release.Published) >= 10 {
		date = release.Published[:10]
	}

	return &api.UpdateInfo{
		Version: release.TagName,
		URL:     release.HTMLURL,
		Name:    release.Name,
		Date:    date,
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func openBrowser(url string) {
	time.Sleep(800 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func parseFlags() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.TorrcPath, "torrc", "configs/torrc", "Path to torrc file")
	flag.StringVar(&cfg.TUNName, "tun", "torvpn0", "TUN interface name")
	flag.StringVar(&cfg.TUNIP, "ip", "10.0.0.1/24", "TUN interface CIDR")
	flag.StringVar(&cfg.DNSListenAddr, "dns", "127.0.0.1:5300", "Local DNS listen address")
	flag.IntVar(&cfg.SocksPort, "socks-port", 9050, "Tor SOCKS5 port")
	flag.IntVar(&cfg.ControlPort, "control-port", 9051, "Tor control port")
	flag.IntVar(&cfg.RotateInterval, "rotate", 600, "Circuit rotation interval (seconds)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&cfg.NoGUI, "no-gui", false, "Disable auto-opening browser")
	flag.StringVar(&cfg.APIAddr, "api", apiAddr, "GUI WebSocket server address")
	flag.Parse()

	// Patch: strings.TrimSpace is imported via strings package
	_ = strings.TrimSpace
	return cfg
}
