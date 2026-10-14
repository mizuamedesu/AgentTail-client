// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"net"
	"net/netip"
	"path/filepath"
	"time"
)

type windowsRoutes struct {
	name, netsh string
	peers       map[netip.Addr]bool
}

func native(name string, ip netip.Addr) (tun.Device, routeManager, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, nil, err
	}
	t, err := tun.CreateTUN(name, MTU)
	if err != nil {
		return nil, nil, err
	}
	r := &windowsRoutes{name: name, netsh: filepath.Join(system, "netsh.exe"), peers: map[netip.Addr]bool{}}
	// Addresses are allocated uniquely by the control plane. Disable DAD on
	// this point-to-point adapter, otherwise Windows initially leaves its /32
	// tentative and refuses application binds despite netsh returning success.
	err = run(r.netsh, "interface", "ipv4", "set", "interface", "interface="+name, "dadtransmits=0", "store=active")
	if err == nil {
		err = run(r.netsh, "interface", "ipv4", "set", "address", "name="+name, "source=static", "address="+ip.String(), "mask=255.255.255.255", "gateway=none", "store=active")
	}
	if err == nil {
		err = run(r.netsh, "interface", "ipv4", "set", "subinterface", name, "mtu=1280", "store=active")
	}
	if err == nil {
		err = waitWindowsAddress(ip)
	}
	if err != nil {
		t.Close()
		return nil, nil, err
	}
	return t, r, nil
}

func waitWindowsAddress(ip netip.Addr) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		// Bind only; do not transmit a probe outside the authorized VPN path.
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(ip.AsSlice())})
		if err == nil {
			return conn.Close()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Windows virtual address did not become usable: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
func (r *windowsRoutes) Add(ip netip.Addr) error {
	if r.peers[ip] {
		return nil
	}
	if err := run(r.netsh, "interface", "ipv4", "add", "route", "prefix="+ip.String()+"/32", "interface="+r.name, "nexthop=0.0.0.0", "store=active"); err != nil {
		return err
	}
	r.peers[ip] = true
	return nil
}
func (r *windowsRoutes) Remove(ip netip.Addr) error {
	if !r.peers[ip] {
		return nil
	}
	err := run(r.netsh, "interface", "ipv4", "delete", "route", "prefix="+ip.String()+"/32", "interface="+r.name, "nexthop=0.0.0.0", "store=active")
	delete(r.peers, ip)
	return err
}
func (r *windowsRoutes) Close() error { return nil } // Wintun adapter close removes its active routes
