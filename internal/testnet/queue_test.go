/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 AgentTail contributors.
 */

package netstack

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestNetworkWriteDoesNotWaitForTUNReader(t *testing.T) {
	tun, network, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := network.DialPingAddr(netip.Addr{}, netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		tun.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { tun.Close(); conn.Close() })
	packet, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 123, Seq: 1, Data: []byte("queued ping")}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := conn.Write(packet); written <- err }()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("network write waited for a TUN reader while holding protocol locks")
	}
	buffer := make([]byte, 1280)
	sizes := make([]int, 1)
	if _, err := tun.Read([][]byte{buffer}, sizes, 0); err != nil || sizes[0] != 20+len(packet) {
		t.Fatal("queued packet was not delivered to the later TUN reader", sizes, err)
	}
}
