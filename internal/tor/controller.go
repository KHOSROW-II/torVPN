// Package tor manages the Tor daemon process and communicates with it
// via the Tor Control Protocol (TCP port 9051).
//
// This package:
//   - Launches Tor as a child process using the embedded torrc
//   - Polls the bootstrap status via GETINFO
//   - Sends SIGNAL NEWNYM to rotate circuits
//   - Exposes SocksAddr() for other packages to reach Tor's SOCKS5 proxy
package tor

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Options configures the Tor controller.
type Options struct {
	TorrcPath   string
	SocksPort   int
	ControlPort int
	Verbose     bool
}

// Controller wraps the Tor process and control connection.
type Controller struct {
	opts    Options
	cmd     *exec.Cmd
	conn    net.Conn
	tp      *textproto.Reader
	socksIP string
}

// New starts the Tor daemon and connects to its control port.
// It writes a minimal torrc if the file doesn't already exist.
func New(opts Options) (*Controller, error) {
	// Ensure torrc exists (write default if absent)
	if err := ensureTorrc(opts); err != nil {
		return nil, fmt.Errorf("torrc setup: %w", err)
	}

	ctrl := &Controller{opts: opts, socksIP: "127.0.0.1"}

	// Resolve Tor binary name per OS
	torBin := "tor"
	if runtime.GOOS == "windows" {
		torBin = "tor.exe"
	}

	// Build absolute path to torrc
	absRc, err := filepath.Abs(opts.TorrcPath)
	if err != nil {
		return nil, fmt.Errorf("torrc abs path: %w", err)
	}

	// Start Tor process
	// #nosec G204 — torBin is a controlled constant, not user input
	ctrl.cmd = exec.Command(torBin, "-f", absRc)
	ctrl.cmd.Stdout = os.Stdout
	ctrl.cmd.Stderr = os.Stderr

	if err := ctrl.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tor: %w (is Tor installed and in PATH?)", err)
	}

	if opts.Verbose {
		log.Printf("[Tor] Started PID=%d torrc=%s", ctrl.cmd.Process.Pid, absRc)
	}

	// Give Tor a moment to bind its control port before we connect
	time.Sleep(2 * time.Second)

	// Connect to the Tor control port
	if err := ctrl.connectControl(); err != nil {
		_ = ctrl.cmd.Process.Kill()
		return nil, fmt.Errorf("connect control port: %w", err)
	}

	// Authenticate with HASHEDPASSWORD
	if err := ctrl.authenticate(); err != nil {
		_ = ctrl.cmd.Process.Kill()
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	return ctrl, nil
}

// connectControl dials the Tor control port with retries.
func (c *Controller) connectControl() error {
	addr := fmt.Sprintf("127.0.0.1:%d", c.opts.ControlPort)
	var (
		conn net.Conn
		err  error
	)
	for attempt := 0; attempt < 10; attempt++ {
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			break
		}
		if c.opts.Verbose {
			log.Printf("[Tor] Control port not ready yet (attempt %d/10)...", attempt+1)
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	c.conn = conn
	c.tp = textproto.NewReader(bufio.NewReader(conn))
	return nil
}

// authenticate reads Tor's cookie file and sends AUTHENTICATE with its hex value.
// CookieAuthentication is simpler and more reliable than HashedControlPassword.
func (c *Controller) authenticate() error {
	// Cookie file lives in the DataDirectory configured in torrc.
	// We look next to the torrc file first, then fall back to "tor-data" relative to CWD.
	cookiePaths := []string{
		filepath.Join(filepath.Dir(c.opts.TorrcPath), "tor-data", "control_auth_cookie"),
		filepath.Join("tor-data", "control_auth_cookie"),
	}

	var cookie []byte
	for _, p := range cookiePaths {
		data, err := os.ReadFile(p)
		if err == nil {
			cookie = data
			if c.opts.Verbose {
				log.Printf("[Tor] Read auth cookie from %s", p)
			}
			break
		}
	}
	if cookie == nil {
		return fmt.Errorf("could not read control_auth_cookie — checked: %v", cookiePaths)
	}

	cmd := fmt.Sprintf("AUTHENTICATE %s", hex.EncodeToString(cookie))
	reply, err := c.sendCommand(cmd)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "250") {
		return fmt.Errorf("auth rejected: %s", reply)
	}
	log.Println("[Tor] Control port authenticated")
	return nil
}

// WaitForBootstrap polls Tor's bootstrap progress until 100% or timeout.
// timeoutSecs is the maximum number of seconds to wait.
func (c *Controller) WaitForBootstrap(timeoutSecs int) error {
	deadline := time.Now().Add(time.Duration(timeoutSecs) * time.Second)
	for time.Now().Before(deadline) {
		reply, err := c.sendCommand("GETINFO status/bootstrap-phase")
		if err != nil {
			return fmt.Errorf("getinfo bootstrap: %w", err)
		}
		// Example reply: 250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
		if strings.Contains(reply, "PROGRESS=100") {
			return nil
		}
		// Extract and log progress
		if c.opts.Verbose {
			if idx := strings.Index(reply, "PROGRESS="); idx != -1 {
				progress := reply[idx+9:]
				if sp := strings.IndexByte(progress, ' '); sp != -1 {
					progress = progress[:sp]
				}
				log.Printf("[Tor] Bootstrap progress: %s%%", progress)
			}
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("bootstrap timed out after %d seconds", timeoutSecs)
}

// NewCircuit sends SIGNAL NEWNYM to rotate all Tor circuits.
func (c *Controller) NewCircuit() error {
	reply, err := c.sendCommand("SIGNAL NEWNYM")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "250") {
		return fmt.Errorf("NEWNYM failed: %s", reply)
	}
	log.Println("[Tor] New circuit requested (NEWNYM)")
	return nil
}

// GetCircuitInfo returns a list of active circuit IDs and their status.
func (c *Controller) GetCircuitInfo() ([]CircuitInfo, error) {
	reply, err := c.sendCommand("GETINFO circuit-status")
	if err != nil {
		return nil, err
	}

	var circuits []CircuitInfo
	for _, line := range strings.Split(reply, "\n") {
		// Lines look like: 250+circuit-status= or  <ID> BUILT <path> ...
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		id, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		circuits = append(circuits, CircuitInfo{
			ID:     id,
			Status: parts[1],
			Path:   strings.Join(parts[2:], " "),
		})
	}
	return circuits, nil
}

// SocksAddr returns the SOCKS5 address for this Tor instance.
func (c *Controller) SocksAddr() string {
	return fmt.Sprintf("%s:%d", c.socksIP, c.opts.SocksPort)
}

// Stop kills the Tor process and closes the control connection.
func (c *Controller) Stop() {
	if c.conn != nil {
		_, _ = c.conn.Write([]byte("QUIT\r\n"))
		_ = c.conn.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		log.Println("[Tor] Process stopped")
	}
}

// sendCommand writes a control command and reads the full response.
// Multi-line responses (250+...250 OK) are collapsed to a single string.
func (c *Controller) sendCommand(cmd string) (string, error) {
	_ = c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()

	_, err := fmt.Fprintf(c.conn, "%s\r\n", cmd)
	if err != nil {
		return "", fmt.Errorf("write command: %w", err)
	}

	var sb strings.Builder
	for {
		line, err := c.tp.ReadLine()
		if err != nil {
			return sb.String(), fmt.Errorf("read reply: %w", err)
		}
		sb.WriteString(line)
		sb.WriteByte('\n')

		// Single-line reply: "250 ..." or error "5xx ..."
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
		// Multi-line reply continues until "250 OK"
		if strings.HasPrefix(line, "250 OK") {
			break
		}
	}
	return sb.String(), nil
}

// CircuitInfo holds parsed circuit information from GETINFO circuit-status.
type CircuitInfo struct {
	ID     int
	Status string
	Path   string // e.g. "$FP1~name1,$FP2~name2,$FP3~name3"
}

// ensureTorrc writes a performance-tuned torrc if none exists.
func ensureTorrc(opts Options) error {
	if _, err := os.Stat(opts.TorrcPath); err == nil {
		return nil // Already exists
	}

	// Create parent directory if needed
	if err := os.MkdirAll(filepath.Dir(opts.TorrcPath), 0o700); err != nil {
		return err
	}

	torrc := fmt.Sprintf(`## TorVPN auto-generated torrc
## Edit this file for advanced tuning. See: https://2019.www.torproject.org/docs/tor-manual.html

SocksPort %d
ControlPort %d
CookieAuthentication 1

## ── Performance tuning ──────────────────────────────────────────────────────
# Reduce circuit build timeout so stalled builds fail fast
CircuitBuildTimeout 10

# How often Tor tries to build a spare preemptive circuit (seconds)
NewCircuitPeriod 30

# Keep circuits alive for 10 minutes max before rotating
MaxCircuitDirtiness 600

# Allow up to 16 simultaneous circuits (more headroom for rotation)
MaxClientCircuitsPending 16

# Cache relay microdescriptors longer to avoid repeated fetches
FetchUselessDescriptors 0

## ── Bridge / obfs4 (uncomment if your ISP throttles Tor) ───────────────────
# UseBridges 1
# ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
# Bridge obfs4 <IP>:<PORT> <FINGERPRINT> cert=<CERT> iat-mode=0

## ── Logging ─────────────────────────────────────────────────────────────────
Log notice stdout
DataDirectory tor-data
`,
		opts.SocksPort, opts.ControlPort)

	return os.WriteFile(opts.TorrcPath, []byte(torrc), 0o600)
}
