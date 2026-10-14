package netdev

import (
	"golang.zx2c4.com/wireguard/tun"
	"net/netip"
)

type darwinRoutes struct {
	name  string
	peers map[netip.Addr]bool
}

func native(_ string, ip netip.Addr) (tun.Device, routeManager, error) {
	t, err := tun.CreateTUN("utun", MTU)
	if err != nil {
		return nil, nil, err
	}
	name, err := t.Name()
	if err != nil {
		t.Close()
		return nil, nil, err
	}
	if err = run("/sbin/ifconfig", name, "inet", ip.String()+"/32", ip.String(), "alias", "up"); err != nil {
		t.Close()
		return nil, nil, err
	}
	return t, &darwinRoutes{name: name, peers: map[netip.Addr]bool{}}, nil
}
func (r *darwinRoutes) Add(ip netip.Addr) error {
	if r.peers[ip] {
		return nil
	}
	if err := run("/sbin/route", "-q", "-n", "add", "-inet", ip.String()+"/32", "-interface", r.name); err != nil {
		return err
	}
	r.peers[ip] = true
	return nil
}
func (r *darwinRoutes) Remove(ip netip.Addr) error {
	if !r.peers[ip] {
		return nil
	}
	err := run("/sbin/route", "-q", "-n", "delete", "-inet", ip.String()+"/32", "-interface", r.name)
	delete(r.peers, ip)
	return err
}
func (r *darwinRoutes) Close() error { return nil } // utun close removes interface routes
