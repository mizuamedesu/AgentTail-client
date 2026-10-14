// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/netdev"
	"github.com/mizuamedesu/AgentTail-client/internal/poc"
	netstack "github.com/mizuamedesu/AgentTail-client/internal/testnet"
	"github.com/mizuamedesu/AgentTail-client/internal/transport"
	"github.com/pion/turn/v5"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type testEndpoint struct {
	info     KeyInfo
	token    string
	expires  time.Time
	desired  string
	revoked  bool
	signals  []Signal
	commands []Command
	acks     map[string]string
	leases   int
	turnIDs  []string
}
type testControl struct {
	mu                        sync.Mutex
	keys                      map[string]*testEndpoint
	sockets                   map[*websocket.Conn]bool
	fail, deny, relayDisabled bool
	ttl                       int
	directBlocked             bool
	turnServers               []transport.ICEServer
	flowServers               []transport.ICEServer
	turnProviders             []string
	turnProvider              func(string) ([]transport.ICEServer, string, int, error)
}

func (c *testControl) notify(event string, keyID string) {
	c.mu.Lock()
	sockets := make([]*websocket.Conn, 0, len(c.sockets))
	for s := range c.sockets {
		sockets = append(sockets, s)
	}
	c.mu.Unlock()
	data, _ := json.Marshal(map[string]string{"type": event, "key_id": keyID})
	for _, s := range sockets {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		s.Write(ctx, websocket.MessageText, data)
		cancel()
	}
}
func (c *testControl) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	var p *testEndpoint
	for _, key := range c.keys {
		if r.Header.Get("Authorization") == "Bearer "+key.token {
			p = key
			break
		}
	}
	if p == nil || p.revoked {
		c.mu.Unlock()
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]string{"code": "UNAUTHENTICATED", "message": "test revoked"}})
		return
	}
	if c.fail {
		c.mu.Unlock()
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]string{"code": "UNAVAILABLE", "message": "test outage"}})
		return
	}
	if r.URL.Path == "/api/agent/events" {
		c.mu.Unlock()
		s, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer s.CloseNow()
		c.mu.Lock()
		c.sockets[s] = true
		c.mu.Unlock()
		defer func() { c.mu.Lock(); delete(c.sockets, s); c.mu.Unlock() }()
		for {
			_, data, err := s.Read(r.Context())
			if err != nil {
				return
			}
			if string(data) == "ping" {
				s.Write(r.Context(), websocket.MessageText, []byte("pong"))
			}
		}
	}
	var output any
	event, target := "", ""
	switch r.URL.Path {
	case "/api/agent/lease":
		var input struct {
			Instance string `json:"instance_id"`
			Desired  string `json:"desired_state"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			c.mu.Unlock()
			w.WriteHeader(400)
			return
		}
		// Match the real Worker: an expired lease becoming live is a peer change
		// even when the process kept the same instance and desired state.
		changed := p.info.Instance != input.Instance || p.desired != input.Desired || !time.Now().Before(p.expires)
		p.info.Instance = input.Instance
		p.desired = input.Desired
		p.expires = time.Now().Add(time.Duration(c.ttl) * time.Second)
		p.leases++
		output = map[string]any{"key_id": p.info.ID, "instance_id": p.info.Instance, "ttl_seconds": c.ttl}
		if changed {
			event = "peers.changed"
		}
	case "/api/agent/sync":
		config := configuration{Key: p.info, Instance: p.info.Instance, Desired: p.desired, Limits: Limits{MaxConnections: 10, BytesPerSecond: 1250000}, RelayAllowed: !c.relayDisabled, ActiveTURN: p.turnIDs, Peers: []KeyInfo{}, Signals: p.signals, Commands: p.commands}
		for _, other := range c.keys {
			if other != p && !other.revoked && !c.deny && other.desired == "up" && p.desired == "up" && time.Now().Before(other.expires) {
				config.Peers = append(config.Peers, other.info)
			}
		}
		config.LeaseRemaining = int((time.Until(p.expires) + time.Second - 1) / time.Second)
		output = config
	case "/api/agent/signal":
		var input struct {
			Instance       string                `json:"instance_id"`
			Target         string                `json:"target_key_id"`
			TargetInstance string                `json:"target_instance"`
			Generation     string                `json:"generation"`
			Kind           string                `json:"kind"`
			Description    transport.Description `json:"description"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			c.mu.Unlock()
			w.WriteHeader(400)
			return
		}
		other := c.keys[input.Target]
		if other == nil || other.info.Instance != input.TargetInstance || p.info.Instance != input.Instance || c.deny {
			c.mu.Unlock()
			w.WriteHeader(403)
			return
		}
		if c.directBlocked {
			candidates := []string{}
			for _, candidate := range input.Description.Candidates {
				if strings.Contains(candidate, " typ relay") {
					candidates = append(candidates, candidate)
				}
			}
			if len(candidates) == 0 {
				candidates = []string{"1 1 udp 2130706431 192.0.2.1 9 typ host"}
			}
			input.Description.Candidates = candidates
		}
		other.signals = append([]Signal{{ID: uuid.NewString(), Source: p.info.ID, Instance: p.info.Instance, Generation: input.Generation, Kind: input.Kind, Description: input.Description}}, other.signals...)
		if len(other.signals) > 100 {
			other.signals = other.signals[:100]
		}
		output = map[string]bool{"accepted": true}
		event, target = "signal.available", other.info.ID
	case "/api/agent/turn":
		var input struct {
			Provider string `json:"provider"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			c.mu.Unlock()
			w.WriteHeader(400)
			return
		}
		if len(c.turnServers) == 0 && c.turnProvider == nil || c.relayDisabled {
			c.mu.Unlock()
			w.WriteHeader(503)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]string{"code": "UNAVAILABLE", "message": "test TURN is unavailable"}})
			return
		}
		id := uuid.NewString()
		p.turnIDs = append(p.turnIDs, id)
		servers, provider := c.turnServers, "cloudflare"
		if len(c.flowServers) > 0 && input.Provider != "cloudflare" {
			servers, provider = c.flowServers, "flow"
		}
		ttl := 60
		if c.turnProvider != nil {
			var err error
			servers, provider, ttl, err = c.turnProvider(input.Provider)
			if err != nil {
				c.mu.Unlock()
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]string{"code": "UNAVAILABLE", "message": "test TURN provider unavailable"}})
				return
			}
		}
		c.turnProviders = append(c.turnProviders, provider)
		output = map[string]any{"iceServers": servers, "provider": provider, "ttl_seconds": ttl, "credential_id": id, "bytes_per_second": 125000}
	default:
		for _, command := range p.commands {
			if r.URL.Path == "/api/agent/commands/"+command.ID+"/ack" {
				var ack struct {
					Status string `json:"status"`
				}
				json.NewDecoder(r.Body).Decode(&ack)
				p.acks[command.ID] = ack.Status
				p.commands = nil
				output = map[string]bool{"acknowledged": true}
			}
		}
		if output == nil {
			c.mu.Unlock()
			w.WriteHeader(503)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]string{"code": "UNAVAILABLE", "message": "test provider not enabled"}})
			return
		}
	}
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": output})
	if event != "" {
		go c.notify(event, target)
	}
}

func waitFor(t *testing.T, timeout time.Duration, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out: " + description)
}

func TestAgentWireGuardControlAndFailureBoundaries(t *testing.T) { agentAcceptance(t, false, false) }
func TestAgentTURNFallbackRotationAndQuota(t *testing.T)         { agentAcceptance(t, false, true) }
func TestNativeTUNAgentAcceptance(t *testing.T) {
	if os.Getenv("AGENTTAIL_TEST_NATIVE_TUN") != "1" {
		t.Skip("explicit opt-in and native TUN privileges required")
	}
	agentAcceptance(t, true, false)
}

func agentAcceptance(t *testing.T, native, relay bool) {
	c := &testControl{keys: map[string]*testEndpoint{}, sockets: map[*websocket.Conn]bool{}, ttl: 60}
	if relay {
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server, err := turn.NewServer(turn.ServerConfig{Realm: "agenttail-agent-test", AuthHandler: func(request *turn.RequestAttributes) (string, []byte, bool) {
			return request.Username, turn.GenerateAuthKey(request.Username, request.Realm, "public-turn-test-password"), true
		}, PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: listener, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}}}})
		if err != nil {
			listener.Close()
			t.Fatal(err)
		}
		defer server.Close()
		c.directBlocked = true
		c.turnServers = []transport.ICEServer{{URLs: []string{"turn:" + listener.LocalAddr().String() + "?transport=udp"}, Username: "test-ephemeral", Credential: "public-turn-test-password"}}
	}
	server := httptest.NewServer(http.HandlerFunc(c.serve))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var keys [2]*Key
	var networks [2]*netstack.Net
	var private [2][]byte
	var meta [2]localstate.Key
	var finished [2]chan struct{}
	for i := range keys {
		pair, err := cryptobox.GenerateWireGuard()
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.NewString()
		private[i] = pair.Private
		meta[i] = localstate.Key{ID: id, Name: fmt.Sprintf("agent-test-%d", i), Public: pair.Public, GrantID: uuid.NewString(), AutoUp: true}
		info := KeyInfo{ID: id, Name: meta[i].Name, Public: pair.Public, Address: fmt.Sprintf("100.126.251.%d", i+1)}
		if native {
			info.Address = fmt.Sprintf("10.203.245.%d", i+1)
			info.CIDR = "10.203.245.0/24"
		}
		c.keys[id] = &testEndpoint{info: info, token: "atk_public-test-" + uuid.NewString(), acks: map[string]string{}}
	}
	for i := range keys {
		i := i
		entry := c.keys[meta[i].ID]
		client, err := api.New(server.URL, entry.token, true)
		if err != nil {
			t.Fatal(err)
		}
		factory := func(id string, private []byte, ip string) (netdev.Interface, error) {
			if native && i == 0 {
				return netdev.New(id, private, ip)
			}
			tun, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(ip)}, nil, netdev.MTU)
			if err != nil {
				return nil, err
			}
			networks[i] = network
			return netdev.NewWithTUN(tun, nil, private)
		}
		key, err := NewKey(Options{Client: client, Metadata: meta[i], Credential: localstate.KeyCredential{KeyID: meta[i].ID, Public: meta[i].Public, Private: private[i], Token: entry.token}, Factory: factory, STUN: []transport.ICEServer{}, LoopbackOnly: true, RelayOnlyForTest: relay})
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
		finished[i] = make(chan struct{})
		go func() { defer close(finished[i]); key.Run(ctx) }()
	}
	defer func() {
		cancel()
		for _, done := range finished {
			<-done
		}
	}()
	connected := func() bool {
		for _, key := range keys {
			s := key.Status()
			if len(s.Peers) != 1 || s.Peers[0].State != "connected" {
				return false
			}
		}
		return true
	}
	connectWait := 12 * time.Second
	if relay {
		connectWait = 50 * time.Second
	}
	waitFor(t, connectWait, "ICE + WireGuard connection", connected)
	if relay {
		for _, key := range keys {
			if key.Status().Peers[0].Path != "relay" {
				t.Fatal("direct failure did not fall back to TURN")
			}
		}
	}
	target := c.keys[meta[1].ID].info.Address
	ping := func() (time.Duration, error) {
		if native {
			return nativePing(keys[0].Status().Address, target)
		}
		conn, err := networks[0].DialPingAddr(netip.Addr{}, netip.MustParseAddr(target))
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		return pingPacket(conn)
	}
	positiveProbes := 0
	pingReady := func() (time.Duration, error) {
		// ICMP/UDP may lose a first packet while WireGuard establishes its
		// handshake. Probe repeatedly, as ordinary ping does, without weakening
		// the one-probe negative ACL check or the measured lease-stop bound.
		var duration time.Duration
		var err error
		for i := 0; i < 8; i++ {
			positiveProbes++
			duration, err = ping()
			if err == nil {
				return duration, nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return duration, err
	}
	elapsed, err := pingReady()
	if err != nil {
		t.Logf("path states: %+v / %+v", keys[0].Status(), keys[1].Status())
		for i, network := range networks {
			if network != nil {
				t.Logf("IP stack %d counters: %+v", i, network.Diagnostics())
			}
		}
		t.Fatal("virtual IP ping:", err)
	}
	listener, err := networks[1].ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(target), 22))
	if err != nil {
		t.Fatal(err)
	}
	dial := networks[0].DialContext
	if native {
		dial = (&net.Dialer{}).DialContext
	}
	sshBudget := 15 * time.Second
	if !native {
		// Race-instrumented virtual TCP can delay a retransmission. Give this
		// fixture the same bounded budget as the virtual network PoC; native
		// TUN acceptance keeps its fifteen-second SSH deadline.
		sshBudget = 30 * time.Second
	}
	sshCtx, sshCancel := context.WithTimeout(ctx, sshBudget)
	sshStarted := time.Now()
	ssh, err := poc.CheckSSH(sshCtx, dial, listener, target)
	sshCancel()
	listener.Close()
	if err != nil {
		t.Fatalf("virtual IP SSH after %s (budget %s): %v", time.Since(sshStarted), sshBudget, err)
	}
	statusJSON, _ := json.Marshal(keys[0].Status())
	if bytes.Contains(statusJSON, []byte(base64.StdEncoding.EncodeToString(private[0]))) || bytes.Contains(statusJSON, []byte(c.keys[meta[0].ID].token)) {
		t.Fatal("status exposed a secret")
	}
	if relay {
		controller := keys[0]
		if keys[1].id < keys[0].id {
			controller = keys[1]
		}
		controller.mu.Lock()
		first := ""
		for _, p := range controller.peers {
			first = p.active.credential.id
		}
		controller.mu.Unlock()
		waitFor(t, 50*time.Second, "TURN credentials and ICE connection rotate before expiry", func() bool {
			controller.mu.Lock()
			defer controller.mu.Unlock()
			for _, p := range controller.peers {
				if p.active != nil && p.active.ice.Stats().Relay && p.active.credential.id != first {
					return true
				}
			}
			return false
		})
		if _, err = pingReady(); err != nil {
			t.Fatal("TURN rotation lost virtual-IP connectivity:", err)
		}
	}

	// Exhausted relay allowance must leave an established direct path usable.
	c.mu.Lock()
	c.relayDisabled = true
	c.directBlocked = false
	c.mu.Unlock()
	c.notify("relay.stopped", "")
	if relay {
		waitFor(t, 10*time.Second, "quota exhausted; direct connectivity resumes", func() bool {
			if !connected() {
				return false
			}
			for _, key := range keys {
				if key.Status().Peers[0].Path != "direct" {
					return false
				}
			}
			return true
		})
	}
	if _, err = pingReady(); err != nil {
		t.Fatal("relay disable stopped direct traffic:", err)
	}
	start := time.Now()
	c.mu.Lock()
	c.deny = true
	c.mu.Unlock()
	c.notify("acl.changed", "")
	waitFor(t, 3*time.Second, "ACL removal", func() bool { return len(keys[0].Status().Peers) == 0 && len(keys[1].Status().Peers) == 0 })
	aclMS := float64(time.Since(start).Microseconds()) / 1000
	if _, err = ping(); err == nil {
		t.Fatal("denied peer still received plaintext IP traffic")
	}
	c.mu.Lock()
	c.deny = false
	c.mu.Unlock()
	c.notify("peers.changed", "")
	waitFor(t, 15*time.Second, "ACL restore", connected)
	for _, action := range []string{"down", "up"} {
		command := Command{ID: uuid.NewString(), Action: action}
		c.mu.Lock()
		c.keys[meta[1].ID].commands = []Command{command}
		c.mu.Unlock()
		c.notify("command.available", meta[1].ID)
		waitFor(t, 6*time.Second, "remote "+action+" command", func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.keys[meta[1].ID].acks[command.ID] == "done" })
		if action == "down" && keys[1].Status().State != "down" {
			t.Fatal("down command left interface active")
		}
	}
	waitFor(t, 15*time.Second, "remote up restores peers", connected)
	// A short server-issued lease exercises exactly the production deadline
	// path without making every ordinary test wait for the production 60 s TTL.
	leaseTTL := 5
	if os.Getenv("AGENTTAIL_TEST_PRODUCTION_LEASE") == "1" {
		leaseTTL = 60
	}
	c.mu.Lock()
	c.ttl = leaseTTL
	before := []int{c.keys[meta[0].ID].leases, c.keys[meta[1].ID].leases}
	c.mu.Unlock()
	for _, key := range keys {
		key.RequestSync()
	}
	waitFor(t, 5*time.Second, "short lease applied after complete client ACL sync", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.keys[meta[0].ID].leases <= before[0] || c.keys[meta[1].ID].leases <= before[1] {
			return false
		}
		for _, key := range keys {
			remaining := key.gate.Remaining()
			if remaining <= 0 || remaining >= time.Duration(leaseTTL)*time.Second {
				return false
			}
		}
		return true
	})
	time.Sleep(150 * time.Millisecond)
	start = time.Now()
	c.mu.Lock()
	c.fail = true
	c.mu.Unlock()
	for _, key := range keys {
		key.RequestSync()
	}
	waitFor(t, time.Duration(leaseTTL+1)*time.Second, "outage expires data authorization", func() bool {
		return !keys[0].Status().Authorized && !keys[1].Status().Authorized && keys[0].Status().Interface == "" && keys[1].Status().Interface == ""
	})
	outageMS := float64(time.Since(start).Microseconds()) / 1000
	c.mu.Lock()
	c.fail = false
	c.ttl = 60
	c.mu.Unlock()
	for _, key := range keys {
		key.RequestSync()
	}
	// Reconnection can need one periodic 20-second sync if both endpoints
	// recover concurrently and a notification is missed, plus ICE dialing.
	waitFor(t, 35*time.Second, "reconnect revalidates peers", connected)
	start = time.Now()
	c.mu.Lock()
	c.keys[meta[1].ID].revoked = true
	c.mu.Unlock()
	c.notify("device.revoked", meta[1].ID)
	waitFor(t, 3*time.Second, "grant revocation", func() bool { return keys[1].Status().State == "unauthorized" && len(keys[0].Status().Peers) == 0 })
	revokeMS := float64(time.Since(start).Microseconds()) / 1000
	if err = keys[1].SetDesired(true); err == nil {
		t.Fatal("revoked credential reactivated locally")
	}
	report := map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "native_tun": native, "local_turn_fallback_and_rotation": relay, "ping_ms": float64(elapsed.Microseconds()) / 1000, "ssh": ssh, "acl_removal_ms": aclMS, "revocation_ms": revokeMS, "outage_stop_ms": outageMS, "tested_lease_seconds": leaseTTL, "scope": "one host, real ICE/WireGuard/IP; mocked scoped control API, not Cloudflare TURN or cross-OS"}
	t.Logf("acceptance: %v", report)
	report["positive_ping_probes"] = positiveProbes
	if path := os.Getenv("AGENTTAIL_ACCEPTANCE_REPORT"); native && path != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		if err = os.WriteFile(path, append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if path := os.Getenv("AGENTTAIL_LOCAL_TURN_REPORT"); relay && path != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		if err = os.WriteFile(path, append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func pingPacket(conn net.Conn) (time.Duration, error) {
	defer conn.SetDeadline(time.Time{})
	timeout := time.Second
	if _, virtual := conn.(*netstack.PingConn); virtual {
		// Race-instrumented virtual stacks on macOS ARM can deliver a valid
		// relay echo after the native one-second probe has expired (observed
		// 1.293s). Keep the native TUN latency gate and bound virtual probes by
		// the enclosing recovery budget instead of closing their socket early.
		timeout = 3 * time.Second
	}
	conn.SetDeadline(time.Now().Add(timeout))
	data := make([]byte, 128)
	rand.Read(data)
	packet, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: 9321, Seq: 1, Data: data}}).Marshal(nil)
	start := time.Now()
	if _, err := conn.Write(packet); err != nil {
		return 0, err
	}
	writeElapsed := time.Since(start)
	buffer := make([]byte, 2048)
	received := 0
	last := "none"
	for {
		var n int
		var err error
		if raw, ok := conn.(*net.IPConn); ok {
			n, _, err = raw.ReadFromIP(buffer)
		} else {
			n, err = conn.Read(buffer)
		}
		if err != nil {
			identifier := uint16(0)
			if ping, ok := conn.(*netstack.PingConn); ok {
				identifier = ping.Identifier()
			}
			return 0, fmt.Errorf("%w (received ICMP=%d, last=%s, socket_id=%d, write_ms=%d, total_ms=%d, started_ms=%d)", err, received, last, identifier, writeElapsed.Milliseconds(), time.Since(start).Milliseconds(), start.UnixMilli())
		}
		received++
		message, err := icmp.ParseMessage(1, buffer[:n])
		if err != nil {
			return 0, err
		}
		echo, isEcho := message.Body.(*icmp.Echo)
		matches := isEcho && bytes.Equal(echo.Data, data)
		last = fmt.Sprintf("type=%v,bytes=%d,payload_match=%t", message.Type, n, matches)
		if isEcho && message.Type == ipv4.ICMPTypeEchoReply && matches {
			return time.Since(start), nil
		}
	}
}
func nativePing(source, target string) (time.Duration, error) {
	connection, err := net.DialIP("ip4:icmp", &net.IPAddr{IP: net.ParseIP(source)}, &net.IPAddr{IP: net.ParseIP(target)})
	if err != nil {
		return 0, err
	}
	defer connection.Close()
	return pingPacket(connection)
}

func TestLocalAgentRejectsForeignKeyAndExport(t *testing.T) {
	m := &Manager{keys: map[string]*managed{}}
	for _, body := range []string{
		`{"key_id":"` + uuid.NewString() + `","action":"up"}`,
		`{"key_id":"` + uuid.NewString() + `","action":"export","token":"atk_stolen"}`,
	} {
		request := httptest.NewRequest("POST", "http://agenttail.local/v1/key", bytes.NewBufferString(body))
		response := httptest.NewRecorder()
		m.handle(response, request)
		if response.Code != 400 && response.Code != 403 {
			t.Fatal("unscoped local request accepted")
		}
	}
	_, err := NewKey(Options{Metadata: localstate.Key{ID: uuid.NewString()}, Credential: localstate.KeyCredential{Token: "account-session"}})
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("account session accepted as key scope")
	}
}
