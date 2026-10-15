// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/netstack"
	"github.com/mizuamedesu/AgentTail-client/internal/transport"
	"golang.zx2c4.com/wireguard/device"
)

type proxyFlow struct {
	cancel context.CancelFunc
	peer   string
	remote net.Conn
}

// Outgoing SOCKS CONNECT reaches only authorized VPN peers. Incoming TCP/UDP
// reaches this host's loopback services at the same port, without an OS TUN.
type userspaceDevice struct {
	*Device
	stack     *netstack.Net
	listener  net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	peers     map[netip.Addr]string
	clients   map[net.Conn]*proxyFlow
	inbound   map[*inboundFlow]struct{}
	address   netip.Addr
	proxyDone func()
	closed    bool
	work      sync.WaitGroup
	closeOnce sync.Once
}

func newUserspace(_ string, private []byte, address, socks string) (Interface, error) {
	ip, err := Address(address)
	if err != nil {
		return nil, err
	}
	proxyAddress, err := netip.ParseAddrPort(socks)
	if err != nil || !proxyAddress.Addr().IsLoopback() {
		return nil, errors.New("SOCKS5 must use a literal loopback address")
	}
	releasePort := func() {}
	if proxyAddress.Port() != 0 {
		releasePort = reserveProxyPort(proxyAddress.Port())
	}
	listener, err := net.Listen("tcp", socks)
	if err != nil {
		releasePort()
		return nil, errors.New("SOCKS5 loopback listener could not be opened; choose another --socks5 port")
	}
	if proxyAddress.Port() == 0 {
		releasePort = reserveProxyPort(uint16(listener.Addr().(*net.TCPAddr).Port))
	}
	tun, stack, err := netstack.CreateNetTUN([]netip.Addr{ip}, nil, MTU)
	if err != nil {
		listener.Close()
		releasePort()
		return nil, err
	}
	device, err := NewWithTUN(tun, nil, private)
	if err != nil {
		listener.Close()
		releasePort()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &userspaceDevice{Device: device.(*Device), stack: stack, listener: listener, ctx: ctx, cancel: cancel, peers: map[netip.Addr]string{}, clients: map[net.Conn]*proxyFlow{}, inbound: map[*inboundFlow]struct{}{}, address: ip, proxyDone: releasePort}
	stack.ForwardTCP(d.forwardTCP)
	stack.ForwardUDP(d.forwardUDP)
	d.work.Add(1)
	go d.serve()
	return d, nil
}

func (d *userspaceDevice) SOCKS5Address() string { return d.listener.Addr().String() }

// Recover a receiver whose peer still encrypts with an old session key. A
// normal application handshake must finish without a competing eager probe.
// Only incoming encrypted data without any observed handshake needs a probe.
type observedDatagram struct {
	transport.Datagram
	data, closed        chan struct{}
	dataOnce, closeOnce sync.Once
	handshake           atomic.Bool
}

func (d *observedDatagram) observe(p []byte, incoming bool) {
	if len(p) < 4 {
		return
	}
	switch binary.LittleEndian.Uint32(p[:4]) {
	case device.MessageInitiationType, device.MessageResponseType, device.MessageCookieReplyType:
		d.handshake.Store(true)
	case device.MessageTransportType:
		if incoming {
			d.dataOnce.Do(func() { close(d.data) })
		}
	}
}
func (d *observedDatagram) stopped() { d.closeOnce.Do(func() { close(d.closed) }) }
func (d *observedDatagram) Read(p []byte) (int, error) {
	n, err := d.Datagram.Read(p)
	if err == nil {
		d.observe(p[:n], true)
	} else {
		d.stopped()
	}
	return n, err
}
func (d *observedDatagram) Write(p []byte) (int, error) {
	d.observe(p, false)
	return d.Datagram.Write(p)
}
func (d *observedDatagram) Close() error {
	d.stopped()
	return d.Datagram.Close()
}

func (d *userspaceDevice) ConnectPeer(id string, link transport.Datagram) error {
	observed := &observedDatagram{Datagram: link, data: make(chan struct{}), closed: make(chan struct{})}
	if err := d.Device.ConnectPeer(id, observed); err != nil {
		return err
	}
	d.Device.mu.Lock()
	p, exists := d.Device.peers[id]
	d.Device.mu.Unlock()
	if !exists {
		return nil
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.work.Add(1)
	d.mu.Unlock()
	go func() {
		defer d.work.Done()
		select {
		case <-d.ctx.Done():
			return
		case <-observed.closed:
			return
		case <-observed.data:
		}
		if observed.handshake.Load() {
			return
		}
		delay := time.Second
		if !d.address.Less(p.address) {
			delay *= 2
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-d.ctx.Done():
			return
		case <-observed.closed:
			return
		case <-timer.C:
		}
		d.Device.mu.Lock()
		defer d.Device.mu.Unlock()
		select {
		case <-observed.closed:
			return
		default:
		}
		if current, ok := d.Device.peers[id]; !ok || current != p || d.Device.closed || d.ctx.Err() != nil || observed.handshake.Load() {
			return
		}
		var public device.NoisePublicKey
		if _, err := hex.Decode(public[:], []byte(p.public)); err == nil {
			if peer := d.Device.wg.LookupPeer(public); peer != nil {
				peer.SendKeepalive()
			}
		}
	}()
	return nil
}

func (d *userspaceDevice) SetPeer(id, public, address string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	if err := d.Device.SetPeer(id, public, address); err != nil {
		return err
	}
	d.peers[netip.MustParseAddr(address)] = id
	return nil
}

func (d *userspaceDevice) RemovePeer(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	err := d.Device.RemovePeer(id)
	for addr, peer := range d.peers {
		if peer == id {
			delete(d.peers, addr)
		}
	}
	for client, flow := range d.clients {
		if flow.peer == id {
			d.closeFlow(client, flow)
		}
	}
	for flow := range d.inbound {
		if flow.peer == id {
			d.closeInbound(flow)
		}
	}
	return err
}

// Called with mu held, including when a dial is still pending.
func (d *userspaceDevice) closeFlow(client net.Conn, flow *proxyFlow) {
	flow.cancel()
	client.Close()
	if flow.remote != nil {
		flow.remote.Close()
	}
}

func (d *userspaceDevice) Close() error {
	d.closeOnce.Do(func() {
		d.cancel()
		d.listener.Close()
		d.mu.Lock()
		d.closed = true
		for client, flow := range d.clients {
			d.closeFlow(client, flow)
		}
		for flow := range d.inbound {
			d.closeInbound(flow)
		}
		d.mu.Unlock()
		d.Device.Close()
		d.work.Wait()
		d.proxyDone()
	})
	return nil
}

func (d *userspaceDevice) serve() {
	defer d.work.Done()
	for {
		client, err := d.listener.Accept()
		if err != nil {
			return
		}
		d.mu.Lock()
		if d.closed || len(d.clients) >= 64 {
			d.mu.Unlock()
			client.Close()
			continue
		}
		ctx, cancel := context.WithCancel(d.ctx)
		flow := &proxyFlow{cancel: cancel}
		d.clients[client] = flow
		d.work.Add(1)
		d.mu.Unlock()
		go func() {
			defer d.work.Done()
			defer func() {
				d.mu.Lock()
				d.closeFlow(client, flow)
				delete(d.clients, client)
				d.mu.Unlock()
			}()
			d.connect(ctx, client, flow)
		}()
	}
}

func socksReply(client net.Conn, code byte) {
	_, _ = client.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

func (d *userspaceDevice) connect(ctx context.Context, client net.Conn, flow *proxyFlow) {
	client.SetDeadline(time.Now().Add(10 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(client, header[:2]); err != nil || header[0] != 5 || header[1] == 0 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{0}) {
		_, _ = client.Write([]byte{5, 255})
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(client, header[:]); err != nil || header[0] != 5 || header[2] != 0 {
		return
	}
	if header[1] != 1 { // CONNECT only; BIND and UDP ASSOCIATE are unsupported.
		socksReply(client, 7)
		return
	}
	var addr netip.Addr
	switch header[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(client, ip[:]); err != nil {
			return
		}
		addr = netip.AddrFrom4(ip)
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(client, length[:]); err != nil {
			return
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, name); err != nil {
			return
		}
		// Some clients encode IP literals as domain names. Never resolve a name
		// with the host resolver or dial a host-network address as a fallback.
		addr, _ = netip.ParseAddr(string(name))
	}
	if !addr.Is4() {
		socksReply(client, 8)
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(client, port[:]); err != nil {
		return
	}
	d.mu.Lock()
	peer, allowed := d.peers[addr]
	if allowed && !d.closed && binary.BigEndian.Uint16(port[:]) != 0 {
		flow.peer = peer
	} else {
		d.mu.Unlock()
		socksReply(client, 2)
		return
	}
	d.mu.Unlock()
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	remote, err := d.stack.DialContextTCPAddrPort(dialCtx, netip.AddrPortFrom(addr, binary.BigEndian.Uint16(port[:])))
	cancel()
	if err != nil {
		socksReply(client, 5)
		return
	}
	d.mu.Lock()
	if d.closed || ctx.Err() != nil || d.peers[addr] != peer {
		d.mu.Unlock()
		remote.Close()
		return
	}
	flow.remote = remote
	d.mu.Unlock()
	socksReply(client, 0)
	client.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(remote, client)
		_ = remote.CloseWrite()
	}()
	_, _ = io.Copy(client, remote)
	// The inbound half may still be waiting for its caller. Close both ends
	// before joining it, including on reset, down, peer removal and revocation.
	client.Close()
	remote.Close()
	<-done
}
