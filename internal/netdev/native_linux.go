package netdev

import (
	"errors"
	"golang.zx2c4.com/wireguard/tun"
	"net/netip"
	"os"
)

type linuxRoutes struct {
	name, ipCommand string
	peers           map[netip.Addr]bool
}

func native(name string, ip netip.Addr) (tun.Device, routeManager, error) {
	command := ""
	for _, path := range []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			command = path
			break
		}
	}
	if command == "" {
		return nil, nil, errors.New("iproute2 is required")
	}
	t, err := tun.CreateTUN(name, MTU)
	if err != nil {
		return nil, nil, err
	}
	r := &linuxRoutes{name: name, ipCommand: command, peers: map[netip.Addr]bool{}}
	if err = run(command, "address", "add", ip.String()+"/32", "dev", name); err == nil {
		err = run(command, "link", "set", "dev", name, "up")
	}
	if err != nil {
		t.Close()
		return nil, nil, err
	}
	return t, r, nil
}
func (r *linuxRoutes) Add(ip netip.Addr) error {
	if r.peers[ip] {
		return nil
	}
	// add, not replace: never overwrite an existing route owned by another VPN.
	if err := run(r.ipCommand, "route", "add", ip.String()+"/32", "dev", r.name, "proto", "static"); err != nil {
		return err
	}
	r.peers[ip] = true
	return nil
}
func (r *linuxRoutes) Remove(ip netip.Addr) error {
	if !r.peers[ip] {
		return nil
	}
	err := run(r.ipCommand, "route", "del", ip.String()+"/32", "dev", r.name, "proto", "static")
	delete(r.peers, ip)
	return err
}
func (r *linuxRoutes) Close() error {
	// Closing the nonpersistent TUN fd removes its addresses and routes.
	return nil
}
