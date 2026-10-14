package agent

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type machineReport struct {
	Hostname   string            `json:"hostname"`
	OS         string            `json:"os"`
	Arch       string            `json:"arch"`
	Interfaces []interfaceReport `json:"interfaces"`
}
type interfaceReport struct {
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
}

// Bound the inventory independently of host configuration and include only
// interface names and IPs. Hardware addresses and credentials are not sent.
func machine() *machineReport {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil // Inventory failure must never interrupt the VPN heartbeat.
	}
	hostname, _ := os.Hostname()
	return &machineReport{Hostname: reportLabel(hostname, 255), OS: runtime.GOOS, Arch: runtime.GOARCH,
		Interfaces: interfaceInventory(interfaces, func(nic net.Interface) ([]net.Addr, error) { return nic.Addrs() })}
}

func reportLabel(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(value, ""))
	// Byte length is also a conservative bound on the server's character limit.
	for len(value) > limit {
		_, width := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-width]
	}
	if value == "" {
		return "unknown"
	}
	return value
}

func interfaceInventory(interfaces []net.Interface, addresses func(net.Interface) ([]net.Addr, error)) []interfaceReport {
	result := make([]interfaceReport, 0, min(len(interfaces), 32))
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Index < interfaces[j].Index })
	for _, nic := range interfaces {
		if len(result) == 32 {
			break
		}
		addrs, err := addresses(nic)
		if err != nil {
			continue
		}
		report := interfaceReport{Name: reportLabel(nic.Name, 128), Up: nic.Flags&net.FlagUp != 0, Addresses: []string{}}
		seen := map[string]bool{}
		for _, addr := range addrs {
			if addr == nil {
				continue
			}
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
				continue
			}
			ip := prefix.String() // Keep the interface's host IP, not the masked subnet.
			if seen[ip] {
				continue
			}
			seen[ip] = true
			report.Addresses = append(report.Addresses, ip)
			if len(report.Addresses) == 16 {
				break
			}
		}
		sort.Strings(report.Addresses)
		result = append(result, report)
	}
	return result
}
