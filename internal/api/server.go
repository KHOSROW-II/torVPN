// Package api implements a local WebSocket server that connects the GUI
// (gui/index.html) to the live TorVPN backend.
//
// The GUI opens a WebSocket to ws://127.0.0.1:7070/ws and exchanges JSON
// messages. Every backend event (log line, stats tick, bootstrap progress,
// circuit info) is pushed to all connected GUI clients in real time.
//
// Message format — backend → GUI:
//
//	{"type":"log",     "level":"notice","msg":"[Tor] Bootstrap 50%","ts":"15:04:05"}
//	{"type":"status",  "state":"connected"|"connecting"|"disconnected"}
//	{"type":"stats",   "txBytes":1234,"rxBytes":5678,"txRate":100,"rxRate":200}
//	{"type":"bootstrap","pct":75,"tag":"loading_descriptors","summary":"Loading relay descriptors"}
//	{"type":"circuit", "circuits":[{"id":1,"status":"BUILT","path":"A~guard,B~mid,C~exit","purpose":"GENERAL"},...]}
//	{"type":"exitip",  "ip":"1.2.3.4","country":"DE"}
//	{"type":"update",  "version":"v1.2.0","url":"https://...","name":"Release name","date":"2026-01-01"}
//
// Message format — GUI → backend:
//
//	{"cmd":"connect"}
//	{"cmd":"disconnect"}
//	{"cmd":"newnym"}
//	{"cmd":"get_status"}
//	{"cmd":"get_circuits"}
//	{"cmd":"check_update"}
//	{"cmd":"set_config","key":"rotate_interval","value":"300"}
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// ── Message types ────────────────────────────────────────────────────────────

// OutMsg is any message sent from backend to GUI.
type OutMsg struct {
	Type    string `json:"type"`
	// log
	Level   string `json:"level,omitempty"`
	Msg     string `json:"msg,omitempty"`
	Ts      string `json:"ts,omitempty"`
	// status
	State   string `json:"state,omitempty"`
	// stats
	TxBytes int64  `json:"txBytes,omitempty"`
	RxBytes int64  `json:"rxBytes,omitempty"`
	TxRate  int64  `json:"txRate,omitempty"`
	RxRate  int64  `json:"rxRate,omitempty"`
	// bootstrap
	Pct     int    `json:"pct,omitempty"`
	Tag     string `json:"tag,omitempty"`
	Summary string `json:"summary,omitempty"`
	// circuit
	Circuits []CircuitMsg `json:"circuits,omitempty"`
	// exit ip
	IP      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	// update
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`
	Name    string `json:"name,omitempty"`
	Date    string `json:"date,omitempty"`
	// config ack
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// CircuitMsg is a single Tor circuit for the GUI.
type CircuitMsg struct {
	ID      int    `json:"id"`
	Status  string `json:"status"`
	Path    string `json:"path"`
	Purpose string `json:"purpose"`
}

// InMsg is a command from the GUI to the backend.
type InMsg struct {
	Cmd   string `json:"cmd"`
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// ── Server ───────────────────────────────────────────────────────────────────

// Callbacks that the main package wires in so the API can drive the VPN.
type Callbacks struct {
	Connect    func() error
	Disconnect func()
	NewCircuit func() error
	GetCircuits func() []CircuitMsg
	GetStatus  func() string // "connected"|"connecting"|"disconnected"
	SetConfig  func(key, value string)
	CheckUpdate func() (*UpdateInfo, error)
}

// UpdateInfo carries GitHub release data.
type UpdateInfo struct {
	Version string
	URL     string
	Name    string
	Date    string
}

// Server is the local WebSocket + HTTP server.
type Server struct {
	addr      string
	cb        Callbacks
	clients   map[*websocket.Conn]struct{}
	mu        sync.RWMutex
	logWriter *LogWriter
	listener  net.Listener
}

// New creates a server bound to addr (e.g. "127.0.0.1:7070").
func New(addr string, cb Callbacks) *Server {
	s := &Server{
		addr:    addr,
		cb:      cb,
		clients: make(map[*websocket.Conn]struct{}),
	}
	s.logWriter = &LogWriter{server: s}
	return s
}

// LogWriter implements io.Writer so we can tee log.SetOutput into the GUI.
type LogWriter struct {
	server *Server
	base   io.Writer
}

func (lw *LogWriter) SetBase(w io.Writer) { lw.base = w }

func (lw *LogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n\r")
	if lw.base != nil {
		lw.base.Write(p)
	}

	// Parse level from log line e.g. "[warn]" or "[notice]" from Tor output,
	// or Go's log format "2006/01/02 15:04:05 file.go:N: message"
	level := "notice"
	lower := strings.ToLower(line)
	if strings.Contains(lower, "[err]") || strings.Contains(lower, "[error]") {
		level = "err"
	} else if strings.Contains(lower, "[warn]") {
		level = "warn"
	} else if strings.Contains(lower, "[debug]") {
		level = "debug"
	} else if strings.Contains(lower, "[info]") {
		level = "info"
	}

	lw.server.Broadcast(OutMsg{
		Type:  "log",
		Level: level,
		Msg:   line,
		Ts:    time.Now().Format("15:04:05"),
	})
	return len(p), nil
}

// GetLogWriter returns the io.Writer to pass to log.SetOutput.
func (s *Server) GetLogWriter() *LogWriter { return s.logWriter }

// Start begins serving. Returns the bound listener so caller can log the port.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api listen %s: %w", s.addr, err)
	}
	s.listener = ln

	mux := http.NewServeMux()

	// WebSocket endpoint
	mux.Handle("/ws", websocket.Handler(s.handleWS))

	// Serve the GUI HTML — embed from ../gui/index.html relative to binary
	mux.HandleFunc("/", s.serveGUI)

	go http.Serve(ln, mux)
	log.Printf("[API] GUI server listening on http://%s", s.addr)
	return nil
}

// Stop closes the listener.
func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

// serveGUI serves the GUI HTML file.
func (s *Server) serveGUI(w http.ResponseWriter, r *http.Request) {
	// Try several paths relative to working directory
	candidates := []string{
		"gui/index.html",
		"../gui/index.html",
		"./gui/index.html",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			http.ServeFile(w, r, p)
			return
		}
	}
	http.Error(w, "GUI not found — place gui/index.html next to the binary", 404)
}

// handleWS handles a single WebSocket connection from the GUI.
func (s *Server) handleWS(ws *websocket.Conn) {
	s.mu.Lock()
	s.clients[ws] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, ws)
		s.mu.Unlock()
		ws.Close()
	}()

	// Send current status immediately on connect
	s.sendTo(ws, OutMsg{Type: "status", State: s.cb.GetStatus()})

	// Read commands from GUI
	dec := json.NewDecoder(ws)
	for {
		var msg InMsg
		if err := dec.Decode(&msg); err != nil {
			break
		}
		s.handleCmd(ws, msg)
	}
}

// handleCmd processes a single command from the GUI.
func (s *Server) handleCmd(ws *websocket.Conn, msg InMsg) {
	switch msg.Cmd {

	case "connect":
		go func() {
			s.Broadcast(OutMsg{Type: "status", State: "connecting"})
			if err := s.cb.Connect(); err != nil {
				s.BroadcastLog("err", "[API] Connect failed: "+err.Error())
				s.Broadcast(OutMsg{Type: "status", State: "disconnected"})
			} else {
				s.Broadcast(OutMsg{Type: "status", State: "connected"})
			}
		}()

	case "disconnect":
		s.cb.Disconnect()
		s.Broadcast(OutMsg{Type: "status", State: "disconnected"})

	case "newnym":
		if err := s.cb.NewCircuit(); err != nil {
			s.BroadcastLog("warn", "[API] New circuit failed: "+err.Error())
		} else {
			s.BroadcastLog("notice", "[Tor] New circuit requested (NEWNYM)")
			time.Sleep(500 * time.Millisecond)
			s.broadcastCircuits()
		}

	case "get_status":
		s.sendTo(ws, OutMsg{Type: "status", State: s.cb.GetStatus()})

	case "get_circuits":
		s.broadcastCircuits()

	case "check_update":
		go func() {
			info, err := s.cb.CheckUpdate()
			if err != nil {
				s.BroadcastLog("warn", "[Update] Check failed: "+err.Error())
				return
			}
			if info != nil {
				s.Broadcast(OutMsg{
					Type:    "update",
					Version: info.Version,
					URL:     info.URL,
					Name:    info.Name,
					Date:    info.Date,
				})
			} else {
				s.BroadcastLog("notice", "[Update] Already on latest version")
			}
		}()

	case "set_config":
		s.cb.SetConfig(msg.Key, msg.Value)
		s.Broadcast(OutMsg{Type: "config_ack", Key: msg.Key, Value: msg.Value})
		s.BroadcastLog("notice", fmt.Sprintf("[Config] %s = %s", msg.Key, msg.Value))
	}
}

func (s *Server) broadcastCircuits() {
	circuits := s.cb.GetCircuits()
	s.Broadcast(OutMsg{Type: "circuit", Circuits: circuits})
}

// Broadcast sends a message to all connected GUI clients.
func (s *Server) Broadcast(msg OutMsg) {
	data, _ := json.Marshal(msg)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ws := range s.clients {
		ws.Write(data)
	}
}

// BroadcastLog is a convenience wrapper for sending a log line.
func (s *Server) BroadcastLog(level, text string) {
	s.Broadcast(OutMsg{
		Type:  "log",
		Level: level,
		Msg:   text,
		Ts:    time.Now().Format("15:04:05"),
	})
}

// BroadcastStats sends bandwidth statistics to the GUI.
func (s *Server) BroadcastStats(txBytes, rxBytes, txRate, rxRate int64) {
	s.Broadcast(OutMsg{
		Type:    "stats",
		TxBytes: txBytes,
		RxBytes: rxBytes,
		TxRate:  txRate,
		RxRate:  rxRate,
	})
}

// BroadcastBootstrap sends a bootstrap progress update.
func (s *Server) BroadcastBootstrap(pct int, tag, summary string) {
	s.Broadcast(OutMsg{
		Type:    "bootstrap",
		Pct:     pct,
		Tag:     tag,
		Summary: summary,
	})
}

// BroadcastExitIP sends the detected exit IP and country.
func (s *Server) BroadcastExitIP(ip, country string) {
	s.Broadcast(OutMsg{
		Type:    "exitip",
		IP:      ip,
		Country: country,
	})
}

func (s *Server) sendTo(ws *websocket.Conn, msg OutMsg) {
	data, _ := json.Marshal(msg)
	ws.Write(data)
}
