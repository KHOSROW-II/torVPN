// tun_windows.go — Windows-specific TUN interface helpers.
//
//go:build windows

package tun

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/songgao/water"
)

// setInterfaceName is a no-op on Windows: WinTUN assigns the adapter name.
func setInterfaceName(cfg *water.Config, _ string) { _ = cfg }

// configureInterface assigns an IP address to the WinTUN adapter using netsh.
// Each argument is a separate exec.Command element — no shell, no quoting issues.
func configureInterface(name, cidr string) error {
	ip, network, err := parseSimpleCIDR(cidr)
	if err != nil {
		return err
	}
	mask := net.IP(network.Mask).String()

	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		name, "static", ip, mask,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set address: %w\n%s", err, out)
	}
	return nil
}

// addDefaultRoute forces all traffic through the TUN by adding two /1 routes
// (0.0.0.0/1 and 128.0.0.0/1) which together cover 0.0.0.0/0 and take
// priority over the existing default gateway route (which is a /0).
//
// Windows route add requires a reachable gateway. For a TUN adapter we use
// the TUN's own IP (tunIP) as the gateway, and specify the interface by index
// so Windows knows which adapter to use.
//
// We also set the adapter metric to 1 (lowest = highest priority) to ensure
// our routes win over any existing ones.
func addDefaultRoute(interfaceName, tunIP string) error {
	// Step 1: set the TUN interface metric to 1 so it wins routing contests
	_ = exec.Command("netsh", "interface", "ip", "set", "interface",
		interfaceName, "metric=1").Run()

	// Step 2: get the interface index for the `route` command
	ifIdx, err := getInterfaceIndex(interfaceName)
	if err != nil {
		// Can't get index — try without it (may work on some Windows versions)
		ifIdx = ""
	}

	// Step 3: get real default gateway so we can add a host route for Tor
	// This keeps Tor itself reachable after we override the default route
	gwIP, gwIface, err := getDefaultGateway()
	if err == nil && gwIP != "" {
		// Add a host route for Tor's guard relay via the real gateway
		// so Tor traffic doesn't loop back into the TUN.
		// We add 0.0.0.0/1 and 128.0.0.0/1 AFTER this, so they win for
		// everything except this specific host route.
		_ = exec.Command("route", "add", "0.0.0.0", "mask", "255.255.255.255",
			gwIP, "metric", "5", "IF", gwIface).Run()
	}

	// Step 4: add the two /1 routes through the TUN
	type route struct{ dst, mask string }
	routes := []route{
		{"0.0.0.0", "128.0.0.0"},
		{"128.0.0.0", "128.0.0.0"},
	}

	for _, r := range routes {
		var args []string
		if ifIdx != "" {
			args = []string{"add", r.dst, "mask", r.mask, tunIP, "metric", "1", "IF", ifIdx}
		} else {
			args = []string{"add", r.dst, "mask", r.mask, tunIP, "metric", "1"}
		}
		cmd := exec.Command("route", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			outStr := strings.TrimSpace(string(out))
			// Delete and re-add if route already exists from a previous run
			if strings.Contains(outStr, "already exists") || strings.Contains(outStr, "The object already exists") {
				delArgs := []string{"delete", r.dst, "mask", r.mask}
				_ = exec.Command("route", delArgs...).Run()
				cmd2 := exec.Command("route", args...)
				if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
					return fmt.Errorf("route add %s/%s: %w\n%s", r.dst, r.mask, err2, out2)
				}
			} else {
				return fmt.Errorf("route add %s/%s: %w\n%s", r.dst, r.mask, err, out)
			}
		}
	}

	// Step 5: point DNS to our leak-proof resolver
	// (The Go DNS server listens on 127.0.0.1:5300, but Windows DNS must use
	// port 53. We set the adapter DNS to 127.0.0.1 which will reach the
	// system's own loopback. The actual redirection to :5300 happens via
	// the TUN packet inspection for UDP/53.)
	_ = exec.Command("netsh", "interface", "ip", "set", "dns",
		interfaceName, "static", "127.0.0.1", "primary").Run()

	return nil
}

// removeDefaultRoute cleans up all routes added by addDefaultRoute.
func removeDefaultRoute(interfaceName string) error {
	_ = exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
	_ = exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
	// Restore DNS on the TUN adapter
	_ = exec.Command("netsh", "interface", "ip", "set", "dns",
		interfaceName, "dhcp").Run()
	return nil
}

// getInterfaceIndex returns the Windows routing interface index for the named adapter.
func getInterfaceIndex(name string) (string, error) {
	// Use `netsh interface ip show interfaces` — more reliable than parsing route print
	cmd := exec.Command("netsh", "interface", "ip", "show", "interfaces")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("netsh show interfaces: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		// Match lines containing our adapter name
		if !strings.Contains(line, name) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err == nil {
			return fields[0], nil
		}
	}

	// Fallback: try `route print` interface table
	cmd2 := exec.Command("route", "print")
	out2, err := cmd2.Output()
	if err != nil {
		return "", fmt.Errorf("route print: %w", err)
	}

	inIfaceSection := false
	for _, line := range strings.Split(string(out2), "\n") {
		if strings.Contains(line, "Interface List") {
			inIfaceSection = true
			continue
		}
		if inIfaceSection && strings.Contains(line, "===") {
			inIfaceSection = false
			continue
		}
		if inIfaceSection && strings.Contains(line, name) {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				// Interface list format: "  13...xx xx xx  <name>"
				// Strip leading dots
				idx := strings.TrimRight(fields[0], ".")
				if _, err := strconv.Atoi(idx); err == nil {
					return idx, nil
				}
			}
		}
	}

	return "", fmt.Errorf("interface %q not found", name)
}

// getDefaultGateway returns the current default gateway IP and interface index.
// Used to preserve Tor's own connectivity when we override the default route.
func getDefaultGateway() (gwIP, ifIdx string, err error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	out, err := cmd.Output()
	if err != nil {
		return "", "", err
	}

	// Look for the IPv4 Route Table section with 0.0.0.0 destination
	// Format: Network Dest  Netmask  Gateway  Interface  Metric
	//         0.0.0.0       0.0.0.0  192.168.1.1  192.168.1.x  25
	inIPv4 := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IPv4 Route Table") || strings.Contains(line, "Active Routes") {
			inIPv4 = true
			continue
		}
		if !inIPv4 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gwIP = fields[2]
			// fields[3] is the interface IP, convert to index via lookup
			idx, _ := getInterfaceByIP(fields[3])
			return gwIP, idx, nil
		}
	}
	return "", "", fmt.Errorf("default gateway not found")
}

// getInterfaceByIP returns the interface index for a given local IP address.
func getInterfaceByIP(ip string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), ip+"/") || addr.String() == ip {
				return strconv.Itoa(iface.Index), nil
			}
		}
	}
	return "", fmt.Errorf("no interface with IP %s", ip)
}

// parseSimpleCIDR parses a CIDR string into IP string and *net.IPNet.
func parseSimpleCIDR(cidr string) (string, *net.IPNet, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", nil, fmt.Errorf("parse cidr: %w", err)
	}
	return ip.String(), network, nil
}
