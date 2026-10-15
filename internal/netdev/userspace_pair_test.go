// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"golang.zx2c4.com/wireguard/device"
)

type userspaceDatagram struct {
	*net.UDPConn
	target      *net.UDPAddr
	initiations *atomic.Int32
}

func (d userspaceDatagram) Write(p []byte) (int, error) {
	if len(p) >= 4 && binary.LittleEndian.Uint32(p[:4]) == device.MessageInitiationType {
		d.initiations.Add(1)
	}
	return d.WriteToUDP(p, d.target)
}

func TestTwoUserspaceReceiversAndFreshWireGuardSession(t *testing.T) {
	first, err := cryptobox.GenerateWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first.Private)
	second, err := cryptobox.GenerateWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second.Private)
	create := func(private []byte, address string) *userspaceDevice {
		t.Helper()
		d, err := newUserspace("test", private, address, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		return d.(*userspaceDevice)
	}
	sender := create(first.Private, "10.203.99.1")
	receiver := create(second.Private, "10.203.99.2")
	const senderID = "00000000-0000-4000-8000-000000000001"
	const receiverID = "00000000-0000-4000-8000-000000000002"
	var initiations [2]atomic.Int32
	if err := sender.SetPeer(receiverID, second.Public, "10.203.99.2"); err != nil {
		t.Fatal(err)
	}
	connect := func(receiver *userspaceDevice, legacy bool) {
		t.Helper()
		if err := receiver.SetPeer(senderID, first.Public, "10.203.99.1"); err != nil {
			t.Fatal(err)
		}
		local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { local.Close() })
		remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { remote.Close() })
		senderLink := userspaceDatagram{local, remote.LocalAddr().(*net.UDPAddr), &initiations[0]}
		var errConnect error
		if legacy {
			// Simulate an older native peer retaining its send keypair when the
			// receiver recreates its stack. It has no on-demand recovery wrapper.
			errConnect = sender.bind.AddPeer(receiverID, senderLink)
		} else {
			errConnect = sender.ConnectPeer(receiverID, senderLink)
		}
		if errConnect != nil {
			t.Fatal(errConnect)
		}
		if err := receiver.ConnectPeer(senderID, userspaceDatagram{remote, local.LocalAddr().(*net.UDPAddr), &initiations[1]}); err != nil {
			t.Fatal(err)
		}
	}
	host, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
	go func() {
		for {
			connection, err := host.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(10 * time.Second))
				io.Copy(connection, connection)
			}()
		}
	}()
	check := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		address := netip.AddrPortFrom(netip.MustParseAddr("10.203.99.2"), uint16(host.Addr().(*net.TCPAddr).Port))
		client, err := sender.stack.DialContextTCPAddrPort(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		client.SetDeadline(time.Now().Add(10 * time.Second))
		want := []byte("TCP between two real encrypted userspace devices")
		if _, err := client.Write(want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, want) {
			t.Fatal("encrypted userspace receiver failed", string(got), err)
		}
	}
	connect(receiver, false)
	// Cold, idle peers must let application traffic initiate the handshake.
	// Sending a recovery probe merely because ICE is attached can compete with
	// an application handshake on a slow machine or during ACL restoration.
	time.Sleep(2500 * time.Millisecond)
	if initiations[0].Load() != 0 || initiations[1].Load() != 0 {
		t.Fatal("idle peers initiated competing WireGuard recovery handshakes")
	}
	check()
	// Retain the sender's WireGuard identity and existing peer keypair while
	// replacing only the receiver, as happens after its authorization expires.
	sender.DisconnectPeer(receiverID)
	receiver.Close()
	receiver = create(second.Private, "10.203.99.2")
	connect(receiver, true)
	check()
	if initiations[1].Load() == 0 {
		t.Fatal("a legacy retained sender did not trigger receiver recovery")
	}
	sender.DisconnectPeer(receiverID)
	receiver.Close()
	receiver = create(second.Private, "10.203.99.2")
	previous := initiations[0].Load()
	connect(receiver, false)
	check()
	if initiations[0].Load() <= previous {
		t.Fatal("a new ICE link reused stale send keys instead of initiating a fresh application handshake")
	}
}
