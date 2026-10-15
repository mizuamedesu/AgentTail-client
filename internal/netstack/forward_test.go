// SPDX-License-Identifier: GPL-3.0-or-later

package netstack

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestForwardedTCPHandshakeStopsOnCancellation(t *testing.T) {
	clientTun, client, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.203.99.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer clientTun.Close()
	serverTun, server, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.203.99.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer serverTun.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, accepted := make(chan struct{}), make(chan error, 1)
	server.ForwardTCP(func(request *TCPRequest) {
		close(started)
		connection, err := request.Accept(ctx)
		if connection != nil {
			connection.Close()
		}
		accepted <- err
	})
	clientContext, stopClient := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopClient()
	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		c, _ := client.DialContext(clientContext, "tcp", "10.203.99.1:2222")
		if c != nil {
			c.Close()
		}
	}()
	packet := make([]byte, 2048)
	sizes := make([]int, 1)
	if _, err := clientTun.Read([][]byte{packet}, sizes, 0); err != nil {
		t.Fatal(err)
	}
	// Deliver the SYN, but never return the SYN-ACK. Cancellation must abort
	// an actual pending accept rather than waiting for TCP's retry deadline.
	if _, err := serverTun.Write([][]byte{packet[:sizes[0]]}, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not receive SYN")
	}
	synAck := make(chan error, 1)
	go func() {
		_, err := serverTun.Read([][]byte{make([]byte, 2048)}, make([]int, 1), 0)
		synAck <- err
	}()
	select {
	case err := <-synAck:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("accept never entered the TCP handshake")
	}
	cancel()
	select {
	case err := <-accepted:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pending accept returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake was retained")
	}
	stopClient()
	<-dialDone
}
