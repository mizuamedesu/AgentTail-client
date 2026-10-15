// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
)

func TestUserspaceListenerPolicyAndProtocol(t *testing.T) {
	for _, address := range []string{"0.0.0.0:1080", "[::]:1080", "localhost:1080", "10.0.0.1:1080", "127.0.0.1:0", "127.0.0.1", "[::1%zone]:1080"} {
		if _, err := (Settings{Mode: "userspace", SOCKS5: address}).Factory(); err == nil {
			t.Fatalf("unsafe listener accepted: %s", address)
		}
	}
	key, err := cryptobox.GenerateWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	device, err := newUserspace("test", key.Private, "100.126.251.1", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	address := device.(Proxy).SOCKS5Address()
	for _, test := range []struct {
		name        string
		input, want []byte
	}{
		{"authentication required", []byte{5, 1, 2}, []byte{5, 255}},
		{"UDP unsupported", []byte{5, 1, 0, 5, 3, 0, 1}, []byte{5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"BIND unsupported", []byte{5, 1, 0, 5, 2, 0, 1}, []byte{5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"IPv6 unsupported", []byte{5, 1, 0, 5, 1, 0, 4}, []byte{5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"host network denied", []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 22}, []byte{5, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Write(test.input); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(test.want))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, test.want) {
				t.Fatalf("SOCKS5 response: %v, %v", got, err)
			}
		})
	}
	// Closing also interrupts a client that has not completed its greeting.
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	device.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("shutdown retained a pending proxy client")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("shutdown left a pending proxy client waiting")
	}
}
