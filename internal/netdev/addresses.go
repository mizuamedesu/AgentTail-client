// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

var privatePools = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}

// Network validates the entire prefix, not just its first address. The old
// shared-space prefix is retained only for a staged existing-VPN migration.
func Network(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() > 30 {
		return netip.Prefix{}, errors.New("invalid VPN IPv4 range")
	}
	if p == AddressPool {
		return p, nil
	}
	for _, pool := range privatePools {
		if pool.Bits() <= p.Bits() && pool.Contains(p.Addr()) {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("VPN IPv4 range must be private")
}

func HostInNetwork(p netip.Prefix, ip netip.Addr) bool {
	if !ip.Is4() || !p.Contains(ip) || ip == p.Addr() {
		return false
	}
	// The first address outside the prefix follows its broadcast address.
	return p.Contains(ip.Next())
}

func CheckNetwork(p netip.Prefix) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, nic := range interfaces {
		if nic.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := nic.Addrs()
		if err != nil {
			return err
		}
		for _, raw := range addresses {
			local, err := netip.ParsePrefix(raw.String())
			if err == nil && local.Addr().Is4() && p.Overlaps(local) {
				return fmt.Errorf("VPN range %s overlaps %s on %s", p, local.Masked(), nic.Name)
			}
		}
	}
	return nil
}

// Pion must not advertise any AgentTail TUN as an underlay, including a TUN
// belonging to a different VPN with a separately configured private range.
var vpnInterfaces = struct {
	sync.RWMutex
	names map[string]int
}{names: map[string]int{}}

func registerVPNInterface(name string, delta int) {
	vpnInterfaces.Lock()
	defer vpnInterfaces.Unlock()
	vpnInterfaces.names[name] += delta
	if vpnInterfaces.names[name] <= 0 {
		delete(vpnInterfaces.names, name)
	}
}
func IsVPNInterface(name string) bool {
	vpnInterfaces.RLock()
	defer vpnInterfaces.RUnlock()
	return vpnInterfaces.names[name] > 0
}
