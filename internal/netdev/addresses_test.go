package netdev

import (
	"net/netip"
	"testing"
)

func TestPrivateVPNRanges(t *testing.T) {
	for _, cidr := range []string{"10.203.0.0/24", "10.0.0.0/8", "172.27.5.0/30", "192.168.20.0/24", "100.96.0.0/11"} {
		p, err := Network(cidr)
		if err != nil {
			t.Fatalf("valid range %s: %v", cidr, err)
		}
		if HostInNetwork(p, p.Addr()) || !HostInNetwork(p, p.Addr().Next()) {
			t.Fatalf("network and host bounds for %s", cidr)
		}
	}
	for _, cidr := range []string{"0.0.0.0/0", "8.8.8.0/24", "10.0.0.1/24", "10.0.0.0/7", "172.0.0.0/8", "192.168.0.0/15", "10.1.0.0/31", "10.1.0.1/32", "100.64.0.0/10", "::/0"} {
		if _, err := Network(cidr); err == nil {
			t.Fatalf("accepted unsafe range %s", cidr)
		}
	}
	p, _ := Network("10.203.0.0/24")
	for _, ip := range []string{"10.203.0.0", "10.203.0.255", "10.203.1.1", "192.168.1.1"} {
		if HostInNetwork(p, netip.MustParseAddr(ip)) {
			t.Fatalf("accepted out-of-range or reserved host %s", ip)
		}
	}
}
