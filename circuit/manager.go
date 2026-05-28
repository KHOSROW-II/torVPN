// Package circuit manages Tor circuit lifecycle:
//   - Periodically rotates circuits via SIGNAL NEWNYM
//   - Fetches relay consensus data to score relays by bandwidth/latency
//   - Provides a CircuitManager that other packages can query for best-relay hints
//
// NOTE: Tor itself handles path selection internally; this manager supplements
// that by nudging Tor (via NEWNYM) when circuits degrade, and by exposing
// relay quality metrics for observability and logging.
package circuit

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TorController is the minimal interface this package needs from the tor package.
type TorController interface {
	NewCircuit() error
	GetCircuitInfo() ([]CircuitInfo, error)
	SocksAddr() string
}

// CircuitInfo mirrors tor.CircuitInfo to avoid circular imports.
type CircuitInfo struct {
	ID     int
	Status string
	Path   string
}

// ManagerOptions configures the circuit manager.
type ManagerOptions struct {
	TorCtrl        TorController
	RotateInterval int  // seconds between forced rotations
	Verbose        bool
}

// Manager runs the background circuit rotation and relay scoring loop.
type Manager struct {
	opts    ManagerOptions
	stopCh  chan struct{}
	relays  []RelayInfo
	mu      sync.RWMutex
	started bool
}

// NewManager creates a Manager but does not start it.
func NewManager(opts ManagerOptions) *Manager {
	return &Manager{
		opts:   opts,
		stopCh: make(chan struct{}),
	}
}

// Start launches the rotation ticker and an initial relay fetch in the background.
func (m *Manager) Start() {
	if m.started {
		return
	}
	m.started = true

	// Fetch relay descriptors once at startup (best-effort; non-fatal)
	go func() {
		if err := m.refreshRelays(); err != nil {
			log.Printf("[Circuit] Relay refresh failed (non-fatal): %v", err)
		}
	}()

	go m.rotateLoop()
	log.Printf("[Circuit] Manager started — rotating every %ds", m.opts.RotateInterval)
}

// Stop signals the rotation loop to exit.
func (m *Manager) Stop() {
	close(m.stopCh)
}

// TopRelays returns the top n relays sorted by bandwidth (highest first).
// Safe to call concurrently.
func (m *Manager) TopRelays(n int) []RelayInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]RelayInfo, 0, n)
	for i, r := range m.relays {
		if i >= n {
			break
		}
		result = append(result, r)
	}
	return result
}

// rotateLoop fires a NEWNYM every RotateInterval seconds.
func (m *Manager) rotateLoop() {
	interval := time.Duration(m.opts.RotateInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Also refresh relay list every 30 minutes
	relayTicker := time.NewTicker(30 * time.Minute)
	defer relayTicker.Stop()

	for {
		select {
		case <-m.stopCh:
			return

		case <-ticker.C:
			if err := m.opts.TorCtrl.NewCircuit(); err != nil {
				log.Printf("[Circuit] Rotation failed: %v", err)
			} else if m.opts.Verbose {
				m.logCircuitStatus()
			}

		case <-relayTicker.C:
			go func() {
				if err := m.refreshRelays(); err != nil {
					log.Printf("[Circuit] Relay refresh failed: %v", err)
				}
			}()
		}
	}
}

// logCircuitStatus fetches and logs current circuit info for debugging.
func (m *Manager) logCircuitStatus() {
	circuits, err := m.opts.TorCtrl.GetCircuitInfo()
	if err != nil {
		log.Printf("[Circuit] GetCircuitInfo: %v", err)
		return
	}
	log.Printf("[Circuit] Active circuits: %d", len(circuits))
	for _, c := range circuits {
		log.Printf("[Circuit]   #%d [%s] %s", c.ID, c.Status, c.Path)
	}
}

// ── Relay scoring ────────────────────────────────────────────────────────────

// RelayInfo holds bandwidth and flag data for a single Tor relay.
type RelayInfo struct {
	Fingerprint string
	Nickname    string
	BandwidthKB int    // observed bandwidth in KB/s from consensus
	Flags       string // e.g. "Fast Stable Guard Exit"
	Score       float64
}

// refreshRelays downloads the Tor network consensus summary and populates
// m.relays sorted by score (bandwidth × stability multiplier).
//
// We use the public Tor metrics API (onionoo) to avoid parsing raw
// consensus documents. In an air-gapped environment, parse /tmp/tor-data/
// microdesc-consensus directly instead.
func (m *Manager) refreshRelays() error {
	// Onionoo details endpoint — bandwidth + flags, no personal data
	const onionooURL = "https://onionoo.torproject.org/summary?type=relay&running=true&fields=fingerprint,nickname,observed_bandwidth,flags"

	// Use a short timeout so startup isn't blocked
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(onionooURL)
	if err != nil {
		return fmt.Errorf("onionoo fetch: %w", err)
	}
	defer resp.Body.Close()

	relays := parseOnionooSummary(resp.Body)

	// Score and sort
	scored := scoreRelays(relays)
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	m.mu.Lock()
	m.relays = scored
	m.mu.Unlock()

	log.Printf("[Circuit] Loaded %d relays from Onionoo", len(scored))
	if m.opts.Verbose && len(scored) > 0 {
		log.Printf("[Circuit] Top relay: %s (%s) bw=%dKB/s score=%.0f",
			scored[0].Nickname, scored[0].Fingerprint[:8],
			scored[0].BandwidthKB, scored[0].Score)
	}
	return nil
}

// scoreRelays assigns a numeric score to each relay.
//
// Score formula:
//
//	score = bandwidth_KB × stability_multiplier
//
// Stability multipliers:
//
//	+50% if relay has the "Stable" flag (long uptime)
//	+20% if relay has the "Fast" flag
//	−80% if relay has the "Exit" flag (we prefer mid-path relays)
//	+10% if relay has the "Guard" flag
func scoreRelays(relays []RelayInfo) []RelayInfo {
	for i := range relays {
		r := &relays[i]
		score := float64(r.BandwidthKB)

		if strings.Contains(r.Flags, "Stable") {
			score *= 1.50
		}
		if strings.Contains(r.Flags, "Fast") {
			score *= 1.20
		}
		if strings.Contains(r.Flags, "Guard") {
			score *= 1.10
		}
		if strings.Contains(r.Flags, "Exit") {
			// We're not selecting exit nodes directly, but penalise them
			// to keep our preference on middle relays for scoring purposes
			score *= 0.20
		}

		r.Score = score
	}
	return relays
}

// parseOnionooSummary does a minimal line-by-line parse of the Onionoo JSON
// response without importing encoding/json to keep the binary small.
// For production use, replace with proper JSON unmarshalling.
//
// Expected JSON structure (abbreviated):
//
//	{"relays":[{"f":"FP","n":"name","b":12345,"fl":["Fast","Stable"]},...],"bridges":[...]}
func parseOnionooSummary(r interface{ Read([]byte) (int, error) }) []RelayInfo {
	// Full JSON parsing with encoding/json is cleaner; using bufio here
	// to demonstrate the low-dependency approach. Replace with:
	//   var resp onionooResponse; json.NewDecoder(r).Decode(&resp)
	// and unmarshal accordingly.

	scanner := bufio.NewScanner(r.(interface {
		Read([]byte) (int, error)
	}))
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024) // 4 MB

	var relays []RelayInfo

	for scanner.Scan() {
		line := scanner.Text()
		// Very simplified: look for lines containing "\"f\":" (fingerprint marker)
		// In production, unmarshal the full response JSON.
		if !strings.Contains(line, `"f":`) {
			continue
		}

		// Extract fields with simple string scanning
		fp := extractJSON(line, `"f":"`, `"`)
		nick := extractJSON(line, `"n":"`, `"`)
		bwStr := extractJSON(line, `"b":`, `,`)
		flags := extractJSON(line, `"fl":[`, `]`)

		bw, _ := strconv.Atoi(strings.TrimSpace(bwStr))

		relays = append(relays, RelayInfo{
			Fingerprint: fp,
			Nickname:    nick,
			BandwidthKB: bw / 1024, // bytes → KB
			Flags:       flags,
		})
	}

	return relays
}

// extractJSON is a naïve key-value extractor for JSON strings.
// start is the prefix before the value; end is the suffix after it.
func extractJSON(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	s = s[i+len(start):]
	j := strings.Index(s, end)
	if j < 0 {
		return s
	}
	return s[:j]
}
