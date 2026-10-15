// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestUserspaceVPNProxyAuthorization(t *testing.T) {
	// The production factory must work without any native TUN factory, host
	// route, CAP_NET_ADMIN, or change to the existing device registration.
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socks := reservation.Addr().String()
	reservation.Close()
	pair := newRecoveryPairWithOptions(t, recoveryOptions{userspace: socks})
	waitFor(t, 15*time.Second, "userspace encrypted VPN", func() bool { return pair.connected("10.203.44.0/24") })
	status := pair.keys[0].Status()
	if status.NetworkMode != "userspace" || status.Interface != "" || status.SOCKS5 != socks || !status.Authorized {
		t.Fatalf("userspace mode misreported: %+v", status)
	}
	pair.mu.Lock()
	peer := pair.networks[1]
	pair.mu.Unlock()
	listener, err := peer.ListenTCPAddrPort(netip.MustParseAddrPort("10.203.44.2:2222"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(30 * time.Second)); _, _ = io.Copy(c, c) }()
		}
	}()
	dialer, err := proxy.SOCKS5("tcp", socks, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dial := func(target string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
	}
	connect := func() net.Conn {
		t.Helper()
		c, err := dial("10.203.44.2:2222")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(5 * time.Second))
		message := "encrypted TCP through userspace SOCKS5"
		if _, err := io.WriteString(c, message); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(message))
		if _, err := io.ReadFull(c, b); err != nil || string(b) != message {
			t.Fatalf("encrypted echo failed: %q, %v", b, err)
		}
		return c
	}
	closed := func(c net.Conn) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := c.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("proxy stream survived loss of authorization")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("proxy stream was left open after loss of authorization")
		}
	}
	for _, target := range []string{"127.0.0.1:22", "10.203.44.99:2222", "1.1.1.1:443", "example.invalid:443"} {
		if c, err := dial(target); err == nil {
			c.Close()
			t.Fatalf("proxy escaped the authorized peer set: %s", target)
		}
	}
	c := connect()
	pair.control.mu.Lock()
	pair.control.deny = true
	pair.control.mu.Unlock()
	pair.keys[0].RequestSync()
	waitFor(t, 5*time.Second, "ACL removal", func() bool { return len(pair.keys[0].Status().Peers) == 0 })
	closed(c)
	if c, err := dial("10.203.44.2:2222"); err == nil {
		c.Close()
		t.Fatal("removed peer remained available through SOCKS5")
	}
	pair.control.mu.Lock()
	pair.control.deny = false
	pair.control.mu.Unlock()
	waitFor(t, 15*time.Second, "ACL restoration", func() bool { return pair.connected("10.203.44.0/24") })
	c = connect()
	if err := pair.keys[0].SetDesired(false); err != nil {
		t.Fatal(err)
	}
	closed(c)
	if connection, err := net.DialTimeout("tcp", socks, time.Second); err == nil {
		connection.Close()
		t.Fatal("VPN down left the proxy listening")
	}
	if err := pair.keys[0].SetDesired(true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "userspace VPN restart", func() bool { return pair.connected("10.203.44.0/24") })
	c = connect()
	pair.control.mu.Lock()
	pair.control.fail = true
	pair.control.mu.Unlock()
	pair.keys[0].RequestSync()
	waitFor(t, 3*time.Second, "control outage", func() bool { return pair.keys[0].Status().Problem == "NETWORK" })
	// Give the real lease watcher a short, non-renewable deadline. The data
	// gate and the listener must close even when the control plane is offline.
	pair.keys[0].gate.Renew(time.Now(), 250*time.Millisecond)
	waitFor(t, 3*time.Second, "userspace lease expiry", func() bool { return pair.keys[0].Status().SOCKS5 == "" })
	closed(c)
	pair.control.mu.Lock()
	pair.control.fail = false
	pair.control.mu.Unlock()
	waitFor(t, 15*time.Second, "userspace lease recovery", func() bool { return pair.connected("10.203.44.0/24") })
	c = connect()
	pair.control.mu.Lock()
	pair.control.keys[pair.keys[0].id].revoked = true
	pair.control.mu.Unlock()
	pair.keys[0].RequestSync()
	waitFor(t, 5*time.Second, "revoked userspace VPN", func() bool { return pair.keys[0].Status().State == "unauthorized" })
	closed(c)
	if connection, err := net.DialTimeout("tcp", socks, time.Second); err == nil {
		connection.Close()
		t.Fatal("revocation left the proxy listening")
	}
}
