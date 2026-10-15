// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"golang.zx2c4.com/wireguard/device"
)

// Both initiations are created before either arrives. Neither response can
// arrive before both initiations have crossed the transport. This models the
// collision that slow scheduling exposes when existing flows resume together.
type crossedHandshakes struct {
	initiated, received [2]chan struct{}
	done                chan struct{}
}

type crossedDatagram struct {
	*net.UDPConn
	target      *net.UDPAddr
	pair        *crossedHandshakes
	index       int
	write, read sync.Once
}

func (d *crossedDatagram) wait(ch <-chan struct{}) error {
	select {
	case <-ch:
		return nil
	case <-d.pair.done:
		return net.ErrClosed
	}
}
func (d *crossedDatagram) Write(p []byte) (int, error) {
	if len(p) >= 4 {
		switch binary.LittleEndian.Uint32(p[:4]) {
		case device.MessageInitiationType:
			d.write.Do(func() { close(d.pair.initiated[d.index]) })
			if err := d.wait(d.pair.initiated[1-d.index]); err != nil {
				return 0, err
			}
		case device.MessageResponseType:
			if err := d.wait(d.pair.received[1-d.index]); err != nil {
				return 0, err
			}
		}
	}
	return d.WriteToUDP(p, d.target)
}
func (d *crossedDatagram) Read(p []byte) (int, error) {
	n, err := d.UDPConn.Read(p)
	if err == nil && n >= 4 && binary.LittleEndian.Uint32(p[:4]) == device.MessageInitiationType {
		d.read.Do(func() { close(d.pair.received[d.index]) })
	}
	return n, err
}

func TestCrossedWireGuardHandshakesDeliverBothDirections(t *testing.T) {
	var endpoints [2]*userspaceDevice
	var wires [2]cryptobox.WireGuardKey
	var sockets [2]*net.UDPConn
	addresses := [2]string{"10.203.98.1", "10.203.98.2"}
	ids := [2]string{"crossed-first", "crossed-second"}
	barrier := &crossedHandshakes{done: make(chan struct{})}
	defer close(barrier.done)
	for i := range endpoints {
		barrier.initiated[i], barrier.received[i] = make(chan struct{}), make(chan struct{})
		wire, err := cryptobox.GenerateWireGuard()
		if err != nil {
			t.Fatal(err)
		}
		wires[i] = wire
		t.Cleanup(func() { clear(wire.Private) })
		endpoint, err := newUserspace(ids[i], wire.Private, addresses[i], "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		endpoints[i] = endpoint.(*userspaceDevice)
		t.Cleanup(func() { endpoint.Close() })
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		sockets[i] = socket
		t.Cleanup(func() { socket.Close() })
	}
	for i, endpoint := range endpoints {
		other := 1 - i
		if err := endpoint.SetPeer(ids[other], wires[other].Public, addresses[other]); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.ConnectPeer(ids[other], &crossedDatagram{UDPConn: sockets[i], target: sockets[other].LocalAddr().(*net.UDPAddr), pair: barrier, index: i}); err != nil {
			t.Fatal(err)
		}
	}
	host, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
	go func() {
		packet := make([]byte, 2048)
		for {
			n, source, err := host.ReadFromUDP(packet)
			if err != nil {
				return
			}
			host.WriteToUDP(packet[:n], source)
		}
	}()
	errors := make(chan error, 2)
	for i, endpoint := range endpoints {
		go func() {
			address := netip.AddrPortFrom(netip.MustParseAddr(addresses[1-i]), uint16(host.LocalAddr().(*net.UDPAddr).Port))
			connection, err := endpoint.stack.DialUDPAddrPort(netip.AddrPort{}, address)
			if err != nil {
				errors <- err
				return
			}
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(2 * time.Second))
			want := []byte("simultaneous encrypted application traffic")
			if _, err = connection.Write(want); err == nil {
				got := make([]byte, len(want))
				_, err = io.ReadFull(connection, got)
				if err == nil && !bytes.Equal(got, want) {
					err = io.ErrUnexpectedEOF
				}
			}
			errors <- err
		}()
	}
	for range endpoints {
		if err := <-errors; err != nil {
			t.Error("crossed handshake blocked application traffic:", err)
		}
	}
}
