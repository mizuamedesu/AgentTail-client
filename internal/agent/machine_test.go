// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"errors"
	"net"
	"strings"
	"testing"
	"unicode/utf8"
)

type reportedAddr string

func (a reportedAddr) Network() string { return "ip" }
func (a reportedAddr) String() string  { return string(a) }

func TestInterfaceInventoryPreservesHostIPsAndBoundsInput(t *testing.T) {
	interfaces := []net.Interface{{Index: 3, Name: "bad"}, {Index: 2, Name: "usb0"}, {Index: 1, Name: "eth0", Flags: net.FlagUp}}
	got := interfaceInventory(interfaces, func(nic net.Interface) ([]net.Addr, error) {
		if nic.Name == "bad" {
			return nil, errors.New("interface removed")
		}
		return []net.Addr{reportedAddr("10.240.255.57/16"), reportedAddr("fe80::4ada:35ff:fe6f:3d7b/64"), reportedAddr("10.240.255.57/16"), reportedAddr("invalid"), reportedAddr("0.0.0.0/0"), reportedAddr("ff02::1/128")}, nil
	})
	if len(got) != 2 || got[0].Name != "eth0" || !got[0].Up || got[1].Up {
		t.Fatalf("incorrect interfaces: %+v", got)
	}
	if len(got[0].Addresses) != 2 || got[0].Addresses[0] != "10.240.255.57/16" || got[0].Addresses[1] != "fe80::4ada:35ff:fe6f:3d7b/64" {
		t.Fatalf("host IP or filtering changed: %+v", got[0])
	}
	large := make([]net.Interface, 50)
	got = interfaceInventory(large, func(net.Interface) ([]net.Addr, error) {
		var addresses []net.Addr
		for i := 1; i <= 30; i++ {
			addresses = append(addresses, &net.IPNet{IP: net.IPv4(10, 0, 0, byte(i)), Mask: net.CIDRMask(24, 32)})
		}
		return addresses, nil
	})
	if len(got) != 32 || len(got[0].Addresses) != 16 {
		t.Fatalf("inventory is not bounded: %d / %d", len(got), len(got[0].Addresses))
	}
	label := reportLabel(strings.Repeat("端末", 100)+"\n\x00", 128)
	if len(label) > 128 || !utf8.ValidString(label) || strings.ContainsAny(label, "\n\x00") {
		t.Fatal("invalid label")
	}
}
