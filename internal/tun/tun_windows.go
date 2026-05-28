// tun_windows.go — Windows-specific TUN interface helpers.
//
// Build constraint: only compiled on Windows.
//
// Requirements:
//   - wintun.dll in the same directory as the .exe (https://www.wintun.net/)
//   - Must run as Administrator
//
// WinTUN is a modern kernel-mode TUN driver for Windows. It is the same
// driver used by WireGuard for Windows. The songgao/water library delegates
// to it automatically on Windows when DeviceType is TUN.

//go:build windows

package tun

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/songgao/water"
)
// setInterfaceName is a no-op on Windows: the interface name is determined
// by WinTUN, not by the caller. water.Config has no Name field on Windows.
func setInterfaceName(cfg *water.Config, _ string) {
	// WinTUN assigns a GUID-based name; name is read-only after creation.
	// Use ComponentID field if you need a specific adapter name.
	_ = cfg
}

// configureInterface assigns the IP address to the named Windows adapter.
// Uses netsh, which is available on all modern Windows versions.
func configureInterface(name, cidr string) error {
	// Parse IP and mask from CIDR
	ip, network, err := parseSimpleCIDR(cidr)
	if err != nil {
		return err
	}
	mask := net.IP(network.Mask).String()

	// Assign the IP using netsh
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%q", name),
		"static", ip, mask,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set address: %w\n%s", err, out)
	}
	return nil
}

// addDefaultRoute routes all traffic (0.0.0.0/0) through the TUN interface.
// This effectively forces all traffic through Tor.
//
// On Windows we add two /1 routes (0.0.0.0/1 and 128.0.0.0/1) to override
// the existing default gateway without deleting it — preserving access to
// the real LAN for the Tor process itself (which uses a split-tunnel exclusion).
func addDefaultRoute(interfaceName, tunIP string) error {
	routes := [][]string{
		{"0.0.0.0", "mask", "128.0.0.0", tunIP, "metric", "1"},
		{"128.0.0.0", "mask", "128.0.0.0", tunIP, "metric", "1"},
	}

	for _, r := range routes {
		args := append([]string{"route", "add"}, r...)
		cmd := exec.Command("route", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("route add %v: %w\n%s", r, err, out)
		}
	}
	return nil
}

// removeDefaultRoute removes the /1 routes added by addDefaultRoute.
func removeDefaultRoute(interfaceName string) error {
	_ = exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
	_ = exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
	return nil
}

// parseSimpleCIDR is a local helper to avoid importing the parent package.
func parseSimpleCIDR(cidr string) (string, *net.IPNet, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", nil, fmt.Errorf("parse cidr: %w", err)
	}
	return ip.String(), network, nil
}
