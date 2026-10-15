package netstack

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestPingReadsReplyQueuedBeforeWaiterRegistration(t *testing.T) {
	address := netip.MustParseAddr("100.96.0.42")
	tun, network, err := CreateNetTUN([]netip.Addr{address}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	conn, err := network.DialPingAddr(netip.Addr{}, address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := []byte("reply must not depend on a future packet")
	packet, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1234, Seq: 1, Data: data}}).Marshal(nil)
	if _, err = conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for conn.ep.Readiness(waiter.EventIn) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("local ICMP reply was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	response := make([]byte, 1280)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatal("queued reply was ignored:", err)
	}
	message, err := icmp.ParseMessage(1, response[:n])
	if err != nil {
		t.Fatal(err)
	}
	echo, ok := message.Body.(*icmp.Echo)
	if !ok || message.Type != ipv4.ICMPTypeEchoReply || !bytes.Equal(echo.Data, data) {
		t.Fatal("invalid local ICMP response")
	}
}
