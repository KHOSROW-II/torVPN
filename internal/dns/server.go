// Package dns implements a leak-proof DNS resolver.
//
// All DNS queries are forwarded through Tor's SOCKS5 proxy to a
// DNS-over-HTTPS resolver (default: Cloudflare 1.1.1.1), preventing:
//   - DNS leaks to your ISP
//   - Plaintext UDP DNS leaks that bypass the TUN
//   - Tor exit-to-resolver eavesdropping (via DoH)
//
// Requests use golang.org/x/net/proxy to dial through Tor's SOCKS5.
//
// DNS-over-HTTPS flow:
//
//	User app → 127.0.0.1:5300 (UDP) → this resolver
//	→ SOCKS5 → Tor → 1.1.1.1 (HTTPS/443) → answer
package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Options configures the DNS server.
type Options struct {
	ListenAddr string // e.g. "127.0.0.1:5300"
	SocksAddr  string // e.g. "127.0.0.1:9050"
	Verbose    bool
}

// Server is a minimal UDP DNS server that proxies all queries via Tor DoH.
type Server struct {
	opts    Options
	conn    *net.UDPConn
	client  *http.Client
	cache   *dnsCache
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewServer creates and binds the DNS server UDP socket.
func NewServer(opts Options) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", opts.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP %s: %w", opts.ListenAddr, err)
	}

	// Build an HTTP client that dials through Tor SOCKS5
	dialer, err := proxy.SOCKS5("tcp", opts.SocksAddr, nil, proxy.Direct)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}

	transport := &http.Transport{
		Dial:                dialer.Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	return &Server{
		opts:   opts,
		conn:   conn,
		client: httpClient,
		cache:  newDNSCache(),
		stopCh: make(chan struct{}),
	}, nil
}

// Serve starts the DNS request handling loop (blocks until Stop is called).
func (s *Server) Serve() {
	buf := make([]byte, 512)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		_ = s.conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[DNS] Read error: %v", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleQuery(packet, addr)
		}()
	}
}

// Stop closes the UDP socket and waits for in-flight handlers.
func (s *Server) Stop() {
	close(s.stopCh)
	_ = s.conn.Close()
	s.wg.Wait()
}

// handleQuery parses the DNS question from the raw UDP packet,
// resolves it via DoH through Tor, and writes the answer back.
func (s *Server) handleQuery(packet []byte, src *net.UDPAddr) {
	question, qtype, err := parseQuestion(packet)
	if err != nil {
		if s.opts.Verbose {
			log.Printf("[DNS] Parse error from %s: %v", src, err)
		}
		return
	}

	cacheKey := fmt.Sprintf("%s:%s", question, qtype)

	// Check cache first
	if cached, ok := s.cache.get(cacheKey); ok {
		if s.opts.Verbose {
			log.Printf("[DNS] Cache hit: %s → %v", question, cached)
		}
		reply := buildResponse(packet, cached)
		_, _ = s.conn.WriteToUDP(reply, src)
		return
	}

	// Resolve via Tor DoH
	addrs, ttl, err := s.resolveDoH(question, qtype)
	if err != nil {
		if s.opts.Verbose {
			log.Printf("[DNS] DoH error for %s: %v", question, err)
		}
		// Send SERVFAIL
		_, _ = s.conn.WriteToUDP(buildServFail(packet), src)
		return
	}

	if s.opts.Verbose {
		log.Printf("[DNS] Resolved %s → %v (TTL %ds)", question, addrs, ttl)
	}

	s.cache.set(cacheKey, addrs, time.Duration(ttl)*time.Second)

	reply := buildResponse(packet, addrs)
	_, _ = s.conn.WriteToUDP(reply, src)
}

// resolveDoH sends a DNS-over-HTTPS request to Cloudflare via Tor.
// Returns resolved addresses and TTL in seconds.
func (s *Server) resolveDoH(name, qtype string) ([]string, int, error) {
	url := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=%s", name, qtype)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return parseDoHResponse(body)
}

// ── DNS wire format helpers ──────────────────────────────────────────────────

// parseQuestion extracts the DNS question name and type from a raw UDP packet.
// This is a minimal parser sufficient for A/AAAA queries.
func parseQuestion(packet []byte) (name, qtype string, err error) {
	if len(packet) < 12 {
		return "", "", fmt.Errorf("packet too short (%d bytes)", len(packet))
	}

	// Skip 12-byte header, then parse QNAME
	offset := 12
	var labels []string

	for offset < len(packet) {
		length := int(packet[offset])
		offset++

		if length == 0 {
			break // root label
		}
		if offset+length > len(packet) {
			return "", "", fmt.Errorf("label overflow")
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}

	if offset+4 > len(packet) {
		return "", "", fmt.Errorf("missing QTYPE/QCLASS")
	}
	qt := (uint16(packet[offset]) << 8) | uint16(packet[offset+1])

	switch qt {
	case 1:
		qtype = "A"
	case 28:
		qtype = "AAAA"
	case 15:
		qtype = "MX"
	default:
		qtype = "A" // fallback
	}

	return strings.Join(labels, "."), qtype, nil
}

// doHResponse is the JSON structure returned by Cloudflare DoH.
type doHResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// parseDoHResponse extracts IP addresses and TTL from a DoH JSON response.
func parseDoHResponse(body []byte) ([]string, int, error) {
	var r doHResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, 0, fmt.Errorf("json: %w", err)
	}
	if r.Status != 0 {
		return nil, 0, fmt.Errorf("dns rcode %d", r.Status)
	}

	var addrs []string
	ttl := 300 // default 5 minutes

	for _, a := range r.Answer {
		if a.Type == 1 || a.Type == 28 { // A or AAAA
			addrs = append(addrs, a.Data)
			if a.TTL > 0 {
				ttl = a.TTL
			}
		}
	}

	if len(addrs) == 0 {
		return nil, 0, fmt.Errorf("no address records in DoH response")
	}
	return addrs, ttl, nil
}

// buildResponse crafts a minimal DNS response packet from the original query.
// It synthesises one A record per address returned by DoH.
func buildResponse(query []byte, addrs []string) []byte {
	// Copy the query header and set QR=1 (response), RA=1 (recursion available)
	hdr := make([]byte, 12)
	copy(hdr, query[:12])
	hdr[2] = 0x81 // QR=1, OPCODE=0, AA=0, TC=0, RD=1
	hdr[3] = 0x80 // RA=1, Z=0, RCODE=0

	// ANCOUNT = number of answer records
	hdr[6] = 0
	hdr[7] = byte(len(addrs))

	// Keep the question section
	question := query[12:]

	var answers []byte
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue // skip IPv6 for simplicity
		}
		// Name pointer back to question (0xC00C)
		answers = append(answers, 0xC0, 0x0C)
		// Type A = 0x0001
		answers = append(answers, 0x00, 0x01)
		// Class IN = 0x0001
		answers = append(answers, 0x00, 0x01)
		// TTL = 300 seconds
		answers = append(answers, 0x00, 0x00, 0x01, 0x2C)
		// RDLENGTH = 4
		answers = append(answers, 0x00, 0x04)
		// RDATA
		answers = append(answers, ip4...)
	}

	result := append(hdr, question...)
	result = append(result, answers...)
	return result
}

// buildServFail returns a DNS SERVFAIL response for the given query.
func buildServFail(query []byte) []byte {
	hdr := make([]byte, 12)
	copy(hdr, query[:12])
	hdr[2] = 0x81
	hdr[3] = 0x82 // RCODE=2 (SERVFAIL)
	return append(hdr, query[12:]...)
}

// ── Simple TTL cache ─────────────────────────────────────────────────────────

type cacheEntry struct {
	addrs   []string
	expires time.Time
}

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

func newDNSCache() *dnsCache {
	c := &dnsCache{entries: make(map[string]cacheEntry)}
	// Purge expired entries every minute
	go func() {
		for range time.Tick(time.Minute) {
			c.purge()
		}
	}()
	return c
}

func (c *dnsCache) get(key string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.addrs, true
}

func (c *dnsCache) set(key string, addrs []string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{addrs: addrs, expires: time.Now().Add(ttl)}
}

func (c *dnsCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
		}
	}
}
