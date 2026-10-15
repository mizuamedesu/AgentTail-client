// SPDX-License-Identifier: GPL-3.0-or-later

package netstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func endpointAddresses(id stack.TransportEndpointID) (netip.AddrPort, netip.AddrPort) {
	remote, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	local, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return netip.AddrPortFrom(remote, id.RemotePort), netip.AddrPortFrom(local, id.LocalPort)
}

// TCPRequest must be accepted or rejected exactly once by its handler.
type TCPRequest struct {
	Source, Destination netip.AddrPort
	request             *tcp.ForwarderRequest
	network             *Net
	id                  stack.TransportEndpointID
}

func (r *TCPRequest) Reject() { r.request.Complete(true) }
func (r *TCPRequest) Accept(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		r.Reject()
		return nil, err
	}
	// CreateEndpoint performs the TCP handshake synchronously. Abort its
	// registered endpoint when authorization disappears, including the race
	// where cancellation arrives just before endpoint registration.
	done, stopped := make(chan struct{}), make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(stopped)
		protocol := ipv4.ProtocolNumber
		if r.Destination.Addr().Is6() {
			protocol = ipv6.ProtocolNumber
		}
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			if ep := r.network.stack.FindTransportEndpoint(protocol, tcp.ProtocolNumber, r.id, 1); ep != nil {
				ep.Abort()
				return
			}
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	})
	var queue waiter.Queue
	ep, err := r.request.CreateEndpoint(&queue)
	close(done)
	if !stop() {
		<-stopped
	}
	r.request.Complete(err != nil)
	if cancelled := ctx.Err(); cancelled != nil {
		if ep != nil {
			ep.Close()
		}
		return nil, cancelled
	}
	if err != nil {
		return nil, errors.New(err.String())
	}
	return gonet.NewTCPConn(&queue, ep), nil
}

func (n *Net) ForwardTCP(handler func(*TCPRequest)) {
	forwarder := tcp.NewForwarder(n.stack, 0, 128, func(request *tcp.ForwarderRequest) {
		source, target := endpointAddresses(request.ID())
		handler(&TCPRequest{Source: source, Destination: target, request: request, network: n, id: request.ID()})
	})
	n.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
}

// UDPRequest is valid only during the synchronous handler call. Accept installs
// a connected endpoint and queues the first datagram before the handler returns.
type UDPRequest struct {
	Source, Destination netip.AddrPort
	network             *Net
	id                  stack.TransportEndpointID
	packet              *stack.PacketBuffer
}

func (r *UDPRequest) Accept() (net.Conn, error) {
	var queue waiter.Queue
	ep, err := r.network.stack.NewEndpoint(udp.ProtocolNumber, r.packet.NetworkProtocolNumber, &queue)
	if err != nil {
		return nil, errors.New(err.String())
	}
	// Connected sessions share a destination port but have distinct peer tuples.
	ep.SocketOptions().SetReuseAddress(true)
	if err = ep.Bind(tcpip.FullAddress{NIC: 1, Addr: r.id.LocalAddress, Port: r.id.LocalPort}); err == nil {
		err = ep.Connect(tcpip.FullAddress{NIC: 1, Addr: r.id.RemoteAddress, Port: r.id.RemotePort})
	}
	if err != nil {
		ep.Close()
		return nil, errors.New(err.String())
	}
	ep.(stack.TransportEndpoint).HandlePacket(r.id, r.packet)
	return gonet.NewUDPConn(&queue, ep), nil
}

func (n *Net) ForwardUDP(handler func(*UDPRequest) bool) {
	n.stack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		source, target := endpointAddresses(id)
		return handler(&UDPRequest{Source: source, Destination: target, network: n, id: id, packet: packet})
	})
}
