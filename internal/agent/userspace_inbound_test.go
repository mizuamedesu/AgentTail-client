// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/netdev"
	"github.com/mizuamedesu/AgentTail-client/internal/poc"
	"golang.zx2c4.com/wireguard/device"
)

func userspaceTestAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

func TestUserspaceVPNIncomingHostServices(t *testing.T) {
	started, phase := time.Now(), "initial"
	socks := userspaceTestAddress(t)
	pair := newRecoveryPairWithOptions(t, recoveryOptions{userspace: socks})
	waitFor(t, 15*time.Second, "userspace receiver", func() bool { return pair.connected("10.203.44.0/24") })
	pair.mu.Lock()
	peer := pair.networks[1]
	pair.mu.Unlock()
	target := func(port int) string { return net.JoinHostPort("10.203.44.1", strconv.Itoa(port)) }
	dial := func(port int, budget time.Duration) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		// A control outage can recreate either peer's IP stack after its lease
		// expires. Always dial the current native endpoint after recovery.
		pair.mu.Lock()
		current := pair.networks[1]
		pair.mu.Unlock()
		return current.DialContext(ctx, "tcp", target(port))
	}

	// A real host service on an arbitrary high port. Finishing a request with
	// TCP FIN must still allow the complete response to travel back to the peer.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	hostConnections := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(20 * time.Second))
			hostConnections <- c
		}
	}()
	connect := func() (net.Conn, net.Conn) {
		t.Helper()
		t.Logf("%s TCP connection at %s", phase, time.Since(started))
		// A WireGuard retry takes five seconds plus jitter. Leave room for a
		// retry and TCP retransmission after restoring authorization/transport.
		client, err := dial(port, 3*device.RekeyTimeout)
		if err != nil {
			t.Fatal("VPN TCP did not reach a host service:", err)
		}
		t.Cleanup(func() { client.Close() })
		var host net.Conn
		select {
		case host = <-hostConnections:
		case <-time.After(5 * time.Second):
			t.Fatal("host listener did not accept the forwarded connection")
		}
		t.Cleanup(func() { host.Close() })
		client.SetDeadline(time.Now().Add(10 * time.Second))
		message := []byte("arbitrary TCP port over WireGuard")
		if _, err := client.Write(message); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(host, got); err != nil || !bytes.Equal(got, message) {
			t.Fatalf("host TCP received %q: %v", got, err)
		}
		if _, err := host.Write(message); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, message) {
			t.Fatalf("VPN TCP received %q: %v", got, err)
		}
		return client, host
	}
	client, host := connect()
	if err := client.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(host); err != nil || len(got) != 0 {
		t.Fatal("host did not receive the forwarded half-close", got, err)
	}
	want := bytes.Repeat([]byte("response after FIN"), 512)
	if _, err := host.Write(want); err != nil {
		t.Fatal(err)
	}
	host.Close()
	if got, err := io.ReadAll(client); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("half-close truncated the response: %d bytes, %v", len(got), err)
	}
	client.Close()

	// Authenticate a real SSH session to another arbitrary host port. No
	// private user key, installed sshd or privileged port is needed for the probe.
	sshListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sshListener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sshStarted := time.Now()
	_, err = poc.CheckSSH(ctx, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return peer.DialContext(ctx, network, target(sshListener.Addr().(*net.TCPAddr).Port))
	}, sshListener, "10.203.44.1")
	t.Logf("authenticated SSH finished after %s (context: %v)", time.Since(sshStarted), ctx.Err())
	if err != nil {
		t.Fatal("authenticated SSH into a userspace host:", err)
	}

	udpHost, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpHost.Close() })
	go func() {
		packet := make([]byte, 65535)
		for {
			n, source, err := udpHost.ReadFromUDP(packet)
			if err != nil {
				return
			}
			udpHost.WriteToUDP(packet[:n], source)
		}
	}()
	udpTarget := netip.MustParseAddrPort(target(udpHost.LocalAddr().(*net.UDPAddr).Port))
	var udpClients []net.Conn
	for i := 0; i < 3; i++ {
		c, err := peer.DialUDPAddrPort(netip.AddrPort{}, udpTarget)
		if err != nil {
			t.Fatal(err)
		}
		udpClients = append(udpClients, c)
		t.Cleanup(func() { c.Close() })
	}
	checkUDP := func(c net.Conn, payload []byte) {
		t.Helper()
		// The fixture shares a 125 kB/s token bucket in both directions. Pace
		// datagrams so this forwarding test does not intentionally trigger loss.
		time.Sleep(100 * time.Millisecond)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if n, err := c.Write(payload); err != nil || n != len(payload) {
			t.Fatal("VPN UDP write", n, err)
		}
		packet := make([]byte, 65535)
		n, err := c.Read(packet)
		if err != nil || !bytes.Equal(packet[:n], payload) {
			t.Fatalf("UDP boundaries/contents changed: want %d bytes, got %d, %v", len(payload), n, err)
		}
	}
	for i, c := range udpClients {
		for _, size := range []int{0, 1, 31, 900, 4096} {
			checkUDP(c, bytes.Repeat([]byte{byte(42 + i)}, size))
		}
	}

	// An inbound VPN connection cannot expose any local AgentTail SOCKS proxy,
	// including one belonging to a completely different VPN on the same host.
	key, err := cryptobox.GenerateWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	otherSOCKS := userspaceTestAddress(t)
	factory, err := (netdev.Settings{Mode: "userspace", SOCKS5: otherSOCKS}).Factory()
	if err != nil {
		t.Fatal(err)
	}
	other, err := factory("other-vpn", key.Private, "10.204.55.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	for _, address := range []string{socks, otherSOCKS} {
		p := int(netip.MustParseAddrPort(address).Port())
		if c, err := dial(p, 2*time.Second); err == nil {
			c.Close()
			t.Fatal("VPN exposed an AgentTail SOCKS gateway", address)
		}
	}

	closedAtHost := func(c net.Conn) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := c.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("host connection remained open after VPN authorization was removed")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("host connection leaked after VPN authorization was removed")
		}
	}
	_, host = connect()
	pair.control.mu.Lock()
	pair.control.deny = true
	pair.control.mu.Unlock()
	pair.keys[0].RequestSync()
	waitFor(t, 5*time.Second, "inbound ACL removal", func() bool { return len(pair.keys[0].Status().Peers) == 0 })
	closedAtHost(host)
	if c, err := dial(port, time.Second); err == nil {
		c.Close()
		t.Fatal("denied peer opened another host connection")
	}
	pair.control.mu.Lock()
	pair.control.deny = false
	pair.control.mu.Unlock()
	phase = "ACL restored"
	waitFor(t, 15*time.Second, "inbound ACL restoration", func() bool { return pair.connected("10.203.44.0/24") })
	_, host = connect()
	if err := pair.keys[0].SetDesired(false); err != nil {
		t.Fatal(err)
	}
	closedAtHost(host)
	if err := pair.keys[0].SetDesired(true); err != nil {
		t.Fatal(err)
	}
	phase = "VPN restarted"
	waitFor(t, 15*time.Second, "inbound restart", func() bool { return pair.connected("10.203.44.0/24") })
	_, host = connect()
	pair.control.mu.Lock()
	pair.control.fail = true
	pair.control.mu.Unlock()
	pair.keys[0].RequestSync()
	waitFor(t, 3*time.Second, "inbound control outage", func() bool { return pair.keys[0].Status().Problem == "NETWORK" })
	pair.keys[0].gate.Renew(time.Now(), 250*time.Millisecond)
	waitFor(t, 3*time.Second, "inbound lease expiry", func() bool { return pair.keys[0].Status().SOCKS5 == "" })
	closedAtHost(host)
	pair.control.mu.Lock()
	pair.control.fail = false
	pair.control.mu.Unlock()
	phase = "lease recovered"
	waitFor(t, 15*time.Second, "inbound lease recovery", func() bool { return pair.connected("10.203.44.0/24") })
	_, host = connect()
	pair.control.mu.Lock()
	pair.control.keys[pair.keys[0].id].revoked = true
	pair.control.mu.Unlock()
	pair.keys[0].RequestSync()
	waitFor(t, 5*time.Second, "inbound grant revocation", func() bool { return pair.keys[0].Status().State == "unauthorized" })
	closedAtHost(host)
}
