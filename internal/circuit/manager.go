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

"github.com/KHOSROW-II/torVPN/internal/tor"
)

// TorController uses tor.CircuitInfo directly — no duplicate type needed.
type TorController interface {
NewCircuit() error
GetCircuitInfo() ([]tor.CircuitInfo, error)
SocksAddr() string
}

type ManagerOptions struct {
TorCtrl        TorController
RotateInterval int
Verbose        bool
}

type Manager struct {
opts    ManagerOptions
stopCh  chan struct{}
relays  []RelayInfo
mu      sync.RWMutex
started bool
}

func NewManager(opts ManagerOptions) *Manager {
return &Manager{opts: opts, stopCh: make(chan struct{})}
}

func (m *Manager) Start() {
if m.started {
return
}
m.started = true
go func() {
if err := m.refreshRelays(); err != nil {
log.Printf("[Circuit] Relay refresh failed (non-fatal): %v", err)
}
}()
go m.rotateLoop()
log.Printf("[Circuit] Manager started — rotating every %ds", m.opts.RotateInterval)
}

func (m *Manager) Stop() { close(m.stopCh) }

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

func (m *Manager) rotateLoop() {
ticker := time.NewTicker(time.Duration(m.opts.RotateInterval) * time.Second)
defer ticker.Stop()
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
log.Printf("[Circuit] Relay refresh: %v", err)
}
}()
}
}
}

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

type RelayInfo struct {
Fingerprint string
Nickname    string
BandwidthKB int
Flags       string
Score       float64
}

func (m *Manager) refreshRelays() error {
const url = "https://onionoo.torproject.org/summary?type=relay&running=true&fields=fingerprint,nickname,observed_bandwidth,flags"
resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(url)
if err != nil {
return fmt.Errorf("onionoo: %w", err)
}
defer resp.Body.Close()

relays := parseOnionooSummary(resp.Body)
scored := scoreRelays(relays)
sort.Slice(scored, func(i, j int) bool { return scored[i].Score > scored[j].Score })

m.mu.Lock()
m.relays = scored
m.mu.Unlock()

log.Printf("[Circuit] Loaded %d relays", len(scored))
return nil
}

func scoreRelays(relays []RelayInfo) []RelayInfo {
for i := range relays {
r := &relays[i]
s := float64(r.BandwidthKB)
if strings.Contains(r.Flags, "Stable") { s *= 1.50 }
if strings.Contains(r.Flags, "Fast")   { s *= 1.20 }
if strings.Contains(r.Flags, "Guard")  { s *= 1.10 }
if strings.Contains(r.Flags, "Exit")   { s *= 0.20 }
r.Score = s
}
return relays
}

func parseOnionooSummary(r interface{ Read([]byte) (int, error) }) []RelayInfo {
scanner := bufio.NewScanner(r.(interface{ Read([]byte) (int, error) }))
scanner.Buffer(make([]byte, 4<<20), 4<<20)
var relays []RelayInfo
for scanner.Scan() {
line := scanner.Text()
if !strings.Contains(line, `"f":`) {
continue
}
bw, _ := strconv.Atoi(strings.TrimSpace(extractJSON(line, `"b":`, `,`)))
relays = append(relays, RelayInfo{
Fingerprint: extractJSON(line, `"f":"`, `"`),
Nickname:    extractJSON(line, `"n":"`, `"`),
BandwidthKB: bw / 1024,
Flags:       extractJSON(line, `"fl":[`, `]`),
})
}
return relays
}

func extractJSON(s, start, end string) string {
i := strings.Index(s, start)
if i < 0 { return "" }
s = s[i+len(start):]
if j := strings.Index(s, end); j >= 0 { return s[:j] }
return s
}
