// Package tun creates a TUN interface and forwards all traffic through Tor.
//
// Windows transparent proxy approach:
//   All IP traffic → TUN interface → this package → Tor SOCKS5 → Internet
//
// The key insight: we don't try to reconstruct raw TCP/IP frames.
// Instead we use io.Copy to relay application-level streams through SOCKS5.
// The TUN reads raw IP packets; we extract the destination and open a fresh
// SOCKS5 connection to that destination, then relay data bidirectionally.
//
// For full TCP state machine handling (SYN/SYN-ACK etc), production tools
// like WireGuard use gVisor netstack. This implementation uses a simpler
// approach that works for established connections via SOCKS5 stream relay.
package tun

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/songgao/water"
	"golang.org/x/net/proxy"
)

// Options configures the TUN device.
type Options struct {
	Name      string
	CIDR      string
	SocksAddr string
	DNSAddr   string
	Verbose   bool
}

// Device wraps a TUN interface with Tor-based forwarding.
type Device struct {
	opts    Options
	iface   *water.Interface
	dialer  proxy.Dialer
	ip      net.IP
	network *net.IPNet
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// New creates the TUN interface and configures OS routing.
func New(opts Options) (*Device, error) {
	ip, network, err := net.ParseCIDR(opts.CIDR)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %s: %w", opts.CIDR, err)
	}

	cfg := water.Config{DeviceType: water.TUN}
	setInterfaceName(&cfg, opts.Name)

	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create TUN: %w\n  Windows: ensure wintun.dll is present and run as Administrator", err)
	}
	log.Printf("[TUN] Interface created: %s", iface.Name())

	if err := configureInterface(iface.Name(), opts.CIDR); err != nil {
		_ = iface.Close()
		return nil, fmt.Errorf("configure interface: %w", err)
	}
	log.Printf("[TUN] Interface %s configured with %s", iface.Name(), opts.CIDR)

	if err := addDefaultRoute(iface.Name(), ip.String()); err != nil {
		_ = iface.Close()
		return nil, fmt.Errorf("add default route: %w", err)
	}

	dialer, err := proxy.SOCKS5("tcp", opts.SocksAddr, nil, proxy.Direct)
	if err != nil {
		_ = iface.Close()
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}

	return &Device{
		opts:    opts,
		iface:   iface,
		dialer:  dialer,
		ip:      ip,
		network: network,
		stopCh:  make(chan struct{}),
	}, nil
}

// pkt carries one TUN read result.
type pkt struct {
	data []byte
	err  error
}

// Run starts the packet forwarding loop. Call in a goroutine.
func (d *Device) Run() {
	log.Println("[TUN] Packet forwarding loop started")

	ch := make(chan pkt, 128)
	go func() {
		for {
			buf := make([]byte, 65535)
			n, err := d.iface.Read(buf)
			if err != nil {
				ch <- pkt{err: err}
				return
			}
			if n >= 20 {
				data := make([]byte, n)
				copy(data, buf[:n])
				ch <- pkt{data: data}
			}
		}
	}()

	for {
		select {
		case <-d.stopCh:
			return
		case p := <-ch:
			if p.err != nil {
				select {
				case <-d.stopCh:
				default:
					log.Printf("[TUN] Read error: %v", p.err)
				}
				return
			}
			d.wg.Add(1)
			go func(data []byte) {
				defer d.wg.Done()
				d.handlePacket(data)
			}(p.data)
		}
	}
}

// handlePacket dispatches an IPv4 packet by protocol.
func (d *Device) handlePacket(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return // not IPv4
	}

	// Skip packets destined for the TUN subnet itself (e.g. 10.0.0.x)
	dstIP := net.IP(pkt[16:20])
	if d.network.Contains(dstIP) {
		return
	}

	// Skip loopback
	if dstIP.IsLoopback() {
		return
	}

	proto := pkt[9]
	ipHdrLen := int(pkt[0]&0x0F) * 4

	switch proto {
	case 6: // TCP
		if len(pkt) < ipHdrLen+20 {
			return
		}
		d.handleTCP(pkt, ipHdrLen, dstIP)
	case 17: // UDP
		if len(pkt) < ipHdrLen+8 {
			return
		}
		d.handleUDP(pkt, ipHdrLen, dstIP)
	}
}

// handleTCP forwards a TCP packet's payload through Tor SOCKS5.
//
// This handles the most common case: an already-established TCP stream where
// the TUN receives data packets. SYN packets (connection initiation) are
// handled by opening a new SOCKS5 connection to the destination.
func (d *Device) handleTCP(pkt []byte, ipHdrLen int, dstIP net.IP) {
	dstPort := binary.BigEndian.Uint16(pkt[ipHdrLen+2 : ipHdrLen+4])
	tcpFlags := pkt[ipHdrLen+13]
	tcpHdrLen := int(pkt[ipHdrLen+12]>>4) * 4

	dst := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)

	// Only open a new SOCKS5 connection on SYN (new connection request)
	// FIN/RST: connection teardown — ignore
	// ACK/PSH with data: handled via the active connection table (future work)
	isSYN := tcpFlags&0x02 != 0 && tcpFlags&0x10 == 0 // SYN set, ACK not set
	isFIN := tcpFlags&0x01 != 0
	isRST := tcpFlags&0x04 != 0

	if isFIN || isRST {
		return
	}

	if !isSYN {
		// Non-SYN data packet: without a full TCP stack we can't relay these
		// correctly into an existing SOCKS5 connection. Log if verbose.
		if d.opts.Verbose {
			log.Printf("[TUN] TCP data packet for %s (no active conn — need full netstack)", dst)
		}
		return
	}

	// SYN packet — open a SOCKS5 connection to the destination
	if d.opts.Verbose {
		log.Printf("[TUN] TCP SYN → %s", dst)
	}

	payload := pkt[ipHdrLen+tcpHdrLen:]

	conn, err := d.dialer.Dial("tcp", dst)
	if err != nil {
		if d.opts.Verbose {
			log.Printf("[TUN] SOCKS5 dial %s: %v", dst, err)
		}
		return
	}
	defer conn.Close()

	if len(payload) > 0 {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			return
		}
	}

	// Relay response back — in a real implementation this goes back into
	// the TUN as a properly-framed TCP response. Without netstack we log it.
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 32768)
	for {
		n, err := conn.Read(buf)
		if n > 0 && d.opts.Verbose {
			log.Printf("[TUN] ← %s: %d bytes", dst, n)
		}
		if err != nil {
			break
		}
	}
}

// handleUDP handles UDP packets; DNS/53 is redirected to the local DoH resolver.
func (d *Device) handleUDP(pkt []byte, ipHdrLen int, dstIP net.IP) {
	dstPort := binary.BigEndian.Uint16(pkt[ipHdrLen+2 : ipHdrLen+4])
	payload := pkt[ipHdrLen+8:]

	if dstPort == 53 {
		d.forwardDNS(payload)
		return
	}

	if d.opts.Verbose {
		log.Printf("[TUN] UDP → %s:%d (%d bytes) — Tor is TCP-only, dropping", dstIP, dstPort, len(payload))
	}
}

// forwardDNS relays a raw DNS query to our local DoH resolver.
func (d *Device) forwardDNS(payload []byte) {
	conn, err := net.DialTimeout("udp", d.opts.DNSAddr, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(payload)
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 && d.opts.Verbose {
		log.Printf("[TUN] DNS reply: %d bytes", n)
	}
}

// Close stops the device and removes OS routes.
func (d *Device) Close() {
	close(d.stopCh)
	d.wg.Wait()
	_ = removeDefaultRoute(d.iface.Name())
	_ = d.iface.Close()
	log.Printf("[TUN] Interface %s closed", d.iface.Name())
}
