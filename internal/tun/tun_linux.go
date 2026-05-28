// tun_linux.go — Linux-specific TUN interface helpers.
//
// Build constraint: only compiled on Linux.
//
// Requirements:
//   - /dev/net/tun must exist (created by loading the tun kernel module)
//   - Must run as root or have CAP_NET_ADMIN
//   - iproute2 (ip command) must be installed

//go:build linux

package tun

import (
	"fmt"
	"os/exec"

	"github.com/songgao/water"
)

// setInterfaceName sets the TUN interface name on Linux.
// The water library uses water.PlatformSpecificParams on Linux.
func setInterfaceName(cfg *water.Config, name string) {
	cfg.Name = name
}

// configureInterface assigns an IP address to the TUN interface using `ip`.
func configureInterface(name, cidr string) error {
	// Assign the address
	cmd := exec.Command("ip", "addr", "add", cidr, "dev", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr add: %w\n%s", err, out)
	}

	// Bring the interface up
	cmd = exec.Command("ip", "link", "set", "dev", name, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up: %w\n%s", err, out)
	}

	return nil
}

// addDefaultRoute forces all traffic through the TUN.
// Uses two /1 routes (covers 0.0.0.0/0) instead of overwriting the real
// default gateway — so the Tor process can still reach the real Internet.
//
// The Tor process itself is excluded via:
//   - Tor connects on lo to the SOCKS port
//   - The split-tunnel exclusion mark (0x1) via ip rule
func addDefaultRoute(interfaceName, tunIP string) error {
	// Mark packets from Tor's UID to bypass the TUN routes.
	// This prevents a routing loop: Tor → TUN → Tor → ...
	// Requires that Tor runs as a separate user (e.g. "debian-tor" or "_tor").
	// Adjust the UID match to match your Tor user.
	//
	// ip rule add not fwmark 0x1 lookup main (applied before the /1 routes)
	_ = exec.Command("ip", "rule", "add", "fwmark", "0x1", "lookup", "main").Run()

	// Add /1 routes to the TUN
	routes := []string{"0.0.0.0/1", "128.0.0.0/1"}
	for _, r := range routes {
		cmd := exec.Command("ip", "route", "add", r, "dev", interfaceName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip route add %s: %w\n%s", r, err, out)
		}
	}

	// Enable IP forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip_forward: %w\n%s", err, out)
	}

	return nil
}

// removeDefaultRoute cleans up routes on shutdown.
func removeDefaultRoute(interfaceName string) error {
	_ = exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", interfaceName).Run()
	_ = exec.Command("ip", "route", "del", "128.0.0.0/1", "dev", interfaceName).Run()
	_ = exec.Command("ip", "rule", "del", "fwmark", "0x1", "lookup", "main").Run()
	return nil
}
