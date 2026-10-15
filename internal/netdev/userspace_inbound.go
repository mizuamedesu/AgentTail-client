// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/netstack"
)

const maxInboundFlows = 256
const udpIdleTimeout = 30 * time.Second

// A peer must not use any VPN's local SOCKS listener as a gateway into another
// peer set. Production ports are reserved before binding, across all devices.
var proxyPorts = struct {
	sync.Mutex
	ports map[uint16]int
}{ports: map[uint16]int{}}

func reserveProxyPort(port uint16) func() {
	proxyPorts.Lock()
	proxyPorts.ports[port]++
	proxyPorts.Unlock()
	return func() {
		proxyPorts.Lock()
		defer proxyPorts.Unlock()
		proxyPorts.ports[port]--
		if proxyPorts.ports[port] == 0 {
			delete(proxyPorts.ports, port)
		}
	}
}
func protectedProxyPort(port uint16) bool {
	proxyPorts.Lock()
	defer proxyPorts.Unlock()
	return proxyPorts.ports[port] != 0
}

type inboundFlow struct {
	ctx        context.Context
	cancel     context.CancelFunc
	peer       string
	address    netip.Addr
	port       uint16
	client     net.Conn
	host       net.Conn
	lastPacket atomic.Int64
}

func (d *userspaceDevice) reserveInbound(source, target netip.AddrPort, tcp bool) *inboundFlow {
	d.mu.Lock()
	defer d.mu.Unlock()
	peer, allowed := d.peers[source.Addr()]
	if d.closed || !allowed || target.Addr() != d.address || source.Port() == 0 || target.Port() == 0 || len(d.inbound) >= maxInboundFlows || tcp && protectedProxyPort(target.Port()) {
		return nil
	}
	ctx, cancel := context.WithCancel(d.ctx)
	f := &inboundFlow{ctx: ctx, cancel: cancel, peer: peer, address: source.Addr(), port: target.Port()}
	f.lastPacket.Store(time.Now().UnixNano())
	d.inbound[f] = struct{}{}
	d.work.Add(1)
	return f
}

// Called with d.mu held. Cancels host dials as well as active socket reads.
func (d *userspaceDevice) closeInbound(f *inboundFlow) {
	f.cancel()
	if f.client != nil {
		f.client.Close()
	}
	if f.host != nil {
		f.host.Close()
	}
}
func (d *userspaceDevice) finishInbound(f *inboundFlow) {
	d.mu.Lock()
	d.closeInbound(f)
	delete(d.inbound, f)
	d.mu.Unlock()
	d.work.Done()
}
func (d *userspaceDevice) attachInbound(f *inboundFlow, client, host net.Conn, tcp bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || f.ctx.Err() != nil || d.peers[f.address] != f.peer || tcp && protectedProxyPort(f.port) {
		if client != nil {
			client.Close()
		}
		if host != nil {
			host.Close()
		}
		return false
	}
	if client != nil {
		f.client = client
	}
	if host != nil {
		f.host = host
	}
	return true
}

func (d *userspaceDevice) hostConnection(f *inboundFlow, network string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.port))))
}

func (d *userspaceDevice) forwardTCP(request *netstack.TCPRequest) {
	f := d.reserveInbound(request.Source, request.Destination, true)
	if f == nil {
		request.Reject()
		return
	}
	defer d.finishInbound(f)
	host, err := d.hostConnection(f, "tcp4")
	if err != nil {
		request.Reject()
		return
	}
	if !d.attachInbound(f, nil, host, true) {
		request.Reject()
		return
	}
	handshake, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	client, err := request.Accept(handshake)
	cancel()
	if err != nil {
		return
	}
	if !d.attachInbound(f, client, nil, true) {
		return
	}
	relayTCP(client, host)
}

func relayTCP(a, b net.Conn) {
	copyHalf := func(dst, src net.Conn) {
		if _, err := io.Copy(dst, src); err != nil {
			a.Close()
			b.Close()
		} else if half, ok := dst.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		} else {
			dst.Close()
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); copyHalf(b, a) }()
	copyHalf(a, b)
	<-done
}

func (d *userspaceDevice) forwardUDP(request *netstack.UDPRequest) bool {
	f := d.reserveInbound(request.Source, request.Destination, false)
	if f == nil {
		return false
	}
	client, err := request.Accept()
	if err != nil || !d.attachInbound(f, client, nil, false) {
		d.finishInbound(f)
		return true
	}
	go func() {
		defer d.finishInbound(f)
		host, err := d.hostConnection(f, "udp4")
		if err != nil || !d.attachInbound(f, nil, host, false) {
			return
		}
		copyPackets := func(dst, src net.Conn) {
			defer client.Close()
			defer host.Close()
			packet := make([]byte, 65535)
			for {
				src.SetReadDeadline(time.Now().Add(udpIdleTimeout))
				n, err := src.Read(packet)
				if err != nil {
					if timeout, ok := err.(net.Error); ok && timeout.Timeout() && time.Since(time.Unix(0, f.lastPacket.Load())) < udpIdleTimeout {
						continue
					}
					return
				}
				f.lastPacket.Store(time.Now().UnixNano())
				dst.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if sent, err := dst.Write(packet[:n]); err != nil || sent != n {
					return
				}
			}
		}
		done := make(chan struct{})
		go func() { defer close(done); copyPackets(host, client) }()
		copyPackets(client, host)
		<-done
	}()
	return true
}
