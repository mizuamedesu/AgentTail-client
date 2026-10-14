package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail/internal/transport"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"golang.org/x/crypto/ssh"
)

func TestEstablishedFlowOutageFallsBackToCloudflare(t *testing.T) {
	stopFlow, servers := outageTURNServer(t)
	verifyEstablishedFlowOutage(t, recoveryOptions{relay: true, configure: func(c *testControl) {
		c.flowServers = servers
	}}, stopFlow, "two agents with real ICE, WireGuard and SSH; local TURN servers represent Flow and Cloudflare; mocked control API")
}

func outageTURNServer(t *testing.T) (func(), []transport.ICEServer) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	generator := &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm:         "agenttail-flow-outage-test",
		LoggerFactory: &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled},
		AuthHandler: func(r *turn.RequestAttributes) (string, []byte, bool) {
			return r.Username, turn.GenerateAuthKey(r.Username, r.Realm, "public-test-password"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: udp, RelayAddressGenerator: generator}},
		ListenerConfigs:   []turn.ListenerConfig{{Listener: tcp, RelayAddressGenerator: generator}},
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := func() { server.Close() }
	t.Cleanup(stop)
	return stop, []transport.ICEServer{{
		URLs:     []string{"turn:" + udp.LocalAddr().String() + "?transport=udp", "turn:" + tcp.Addr().String() + "?transport=tcp"},
		Username: "public-test-user", Credential: "public-test-password",
	}}
}

// Observing this predicate must not wake the agents: recovery must be driven by
// production ICE failure detection, credential rotation and synchronization.
func (p *recoveryPair) usingRelay(provider string) bool {
	for _, key := range p.keys {
		key.mu.Lock()
		connected := len(key.peers) == 1
		for _, peer := range key.peers {
			connected = connected && peer.active != nil && peer.active.credential != nil &&
				peer.active.credential.provider == provider && peer.active.ice.Stats().Relay
		}
		key.mu.Unlock()
		if !connected {
			return false
		}
	}
	return true
}

func verifyEstablishedFlowOutage(t *testing.T, options recoveryOptions, stopFlow func(), scope string) {
	t.Helper()
	pair := newRecoveryPairWithOptions(t, options)
	waitFor(t, 45*time.Second, "established Flow relay on both agents", func() bool { return pair.usingRelay("flow") })
	waitFor(t, 10*time.Second, "encrypted ping before outage", func() bool { return pair.ping("10.203.44.2") })
	client := outageSSHClient(t, pair)
	if err := outageSSHRequest(client, "before outage"); err != nil {
		t.Fatal("SSH before outage:", err)
	}
	pair.mu.Lock()
	originalTUNs := pair.tuns
	pair.mu.Unlock()
	instances := [2]string{pair.keys[0].instance, pair.keys[1].instance}
	// The control API deliberately continues to return primary credentials.
	// Clients must detect the dead transport and request Cloudflare themselves.
	stopFlow()
	started := time.Now()
	t.Log("established Flow transport stopped; existing SSH connection kept open")
	type sshResult struct {
		err     error
		elapsed time.Duration
	}
	sshDone := make(chan sshResult, 1)
	go func() {
		err := outageSSHRequest(client, "same SSH connection after outage")
		sshDone <- sshResult{err, time.Since(started)}
	}()
	waitFor(t, 100*time.Second, "automatic Cloudflare recovery on both agents", func() bool { return pair.usingRelay("cloudflare") })
	recovered := time.Since(started)
	waitFor(t, 10*time.Second, "encrypted ping after outage", func() bool { return pair.ping("10.203.44.2") })
	var sshElapsed time.Duration
	select {
	case result := <-sshDone:
		if result.err != nil {
			t.Fatal("existing SSH connection did not survive:", result.err)
		}
		sshElapsed = result.elapsed
	case <-time.After(25 * time.Second):
		t.Fatal("existing SSH connection did not resume")
	}
	pair.mu.Lock()
	currentTUNs := pair.tuns
	pair.mu.Unlock()
	if currentTUNs != originalTUNs {
		t.Fatal("failover recreated a VPN interface")
	}
	for i, key := range pair.keys {
		status := key.Status()
		if key.instance != instances[i] || status.State != "up" || status.Address != [2]string{"10.203.44.1", "10.203.44.2"}[i] {
			t.Fatal("failover changed the client instance or VPN IP")
		}
	}
	pair.control.mu.Lock()
	providers := append([]string(nil), pair.control.turnProviders...)
	pair.control.mu.Unlock()
	report := map[string]any{
		"time": started.UTC().Format(time.RFC3339Nano), "scope": scope,
		"initial_provider": "flow", "final_provider": "cloudflare",
		"automatic_recovery_ms":   float64(recovered.Microseconds()) / 1000,
		"existing_ssh_resumed_ms": float64(sshElapsed.Microseconds()) / 1000,
		"existing_ssh_survived":   true, "encrypted_ping_after_outage": true,
		"vpn_ips_unchanged": true, "vpn_interfaces_unchanged": true, "client_instances_unchanged": true,
		"manual_sync_or_restart": false, "provider_requests": providers,
		"primary_credential_api_remained_available": true,
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encoded))
	if path := os.Getenv("AGENTTAIL_FLOW_OUTAGE_REPORT"); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func outageSSHRequest(client *ssh.Client, value string) error {
	ok, payload, err := client.SendRequest("agenttail-outage-test", true, []byte(value))
	if err != nil {
		return err
	}
	if !ok || !bytes.Equal(payload, []byte(value)) {
		return errors.New("SSH reply did not match")
	}
	return nil
}

func outageSSHClient(t *testing.T, pair *recoveryPair) *ssh.Client {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "outage-test" || !bytes.Equal(key.Marshal(), clientKey.PublicKey().Marshal()) {
			return nil, errors.New("unauthorized SSH key")
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(host)
	pair.mu.Lock()
	networks := pair.networks
	pair.mu.Unlock()
	listener, err := networks[1].ListenTCPAddrPort(netip.MustParseAddrPort("10.203.44.2:22"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(140 * time.Second))
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go func() {
			for ch := range channels {
				ch.Reject(ssh.UnknownChannelType, "requests only")
			}
		}()
		for request := range requests {
			request.Reply(request.Type == "agenttail-outage-test", request.Payload)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := networks[0].DialContext(ctx, "tcp", "10.203.44.2:22")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(140 * time.Second))
	cc, channels, requests, err := ssh.NewClientConn(conn, "10.203.44.2:22", &ssh.ClientConfig{
		User: "outage-test", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientKey)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(cc, channels, requests)
	t.Cleanup(func() {
		client.Close()
		listener.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Error("SSH test server did not stop")
		}
	})
	return client
}
