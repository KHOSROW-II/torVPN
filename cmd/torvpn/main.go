// TorVPN - A transparent VPN that routes all traffic through the Tor network.
// Supports Windows (primary) and Linux (secondary) via TUN/TAP interface.
//
// Architecture:
//   main.go → TUN Engine ↔ Tor SOCKS5 Proxy ↔ Tor Network
//              ↕
//           DNS Resolver (prevents DNS leaks)
//
// Usage:
//   Windows: run as Administrator
//   Linux:   run as root (or with CAP_NET_ADMIN)

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yourusername/torvpn/internal/circuit"
	"github.com/yourusername/torvpn/internal/dns"
	"github.com/yourusername/torvpn/internal/tor"
	"github.com/yourusername/torvpn/internal/tun"
)

// Config holds all runtime configuration for TorVPN.
type Config struct {
	TorrcPath      string // Path to torrc configuration file
	TUNName        string // TUN interface name (e.g. "torvpn0")
	TUNIP          string // TUN interface IP (e.g. "10.0.0.1/24")
	DNSListenAddr  string // Local DNS listener address
	SocksPort      int    // Tor SOCKS5 port
	ControlPort    int    // Tor control port
	RotateInterval int    // Circuit rotation interval in seconds
	Verbose        bool   // Enable verbose logging
}

func main() {
	cfg := parseFlags()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[TorVPN] Starting up...")

	// ── 1. Start Tor daemon ──────────────────────────────────────────────────
	torCtrl, err := tor.New(tor.Options{
		TorrcPath:   cfg.TorrcPath,
		SocksPort:   cfg.SocksPort,
		ControlPort: cfg.ControlPort,
		Verbose:     cfg.Verbose,
	})
	if err != nil {
		log.Fatalf("[TorVPN] Failed to start Tor: %v", err)
	}
	defer torCtrl.Stop()

	log.Println("[TorVPN] Tor daemon started, waiting for bootstrap...")
	if err := torCtrl.WaitForBootstrap(300); err != nil {
		log.Fatalf("[TorVPN] Tor bootstrap failed: %v", err)
	}
	log.Println("[TorVPN] Tor bootstrap complete (100%)")

	// ── 2. Start circuit manager ─────────────────────────────────────────────
	cm := circuit.NewManager(circuit.ManagerOptions{
		TorCtrl:        torCtrl,
		RotateInterval: cfg.RotateInterval,
		Verbose:        cfg.Verbose,
	})
	cm.Start()
	defer cm.Stop()

	// ── 3. Start leak-proof DNS resolver ─────────────────────────────────────
	dnsServer, err := dns.NewServer(dns.Options{
		ListenAddr: cfg.DNSListenAddr,
		SocksAddr:  torCtrl.SocksAddr(),
		Verbose:    cfg.Verbose,
	})
	if err != nil {
		log.Fatalf("[TorVPN] Failed to start DNS server: %v", err)
	}
	go dnsServer.Serve()
	defer dnsServer.Stop()
	log.Printf("[TorVPN] DNS resolver listening on %s", cfg.DNSListenAddr)

	// ── 4. Create and configure TUN interface ────────────────────────────────
	tunDev, err := tun.New(tun.Options{
		Name:      cfg.TUNName,
		CIDR:      cfg.TUNIP,
		SocksAddr: torCtrl.SocksAddr(),
		DNSAddr:   cfg.DNSListenAddr,
		Verbose:   cfg.Verbose,
	})
	if err != nil {
		log.Fatalf("[TorVPN] Failed to create TUN device: %v", err)
	}
	defer tunDev.Close()

	// ── 5. Start packet routing loop ─────────────────────────────────────────
	go tunDev.Run()
	log.Printf("[TorVPN] TUN interface %s up — all traffic routed through Tor", cfg.TUNName)
	log.Println("[TorVPN] Press Ctrl+C to stop")

	// ── 6. Wait for termination signal ───────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[TorVPN] Shutting down gracefully...")
}

// parseFlags parses command-line flags and returns a populated Config.
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
	flag.Parse()

	return cfg
}
