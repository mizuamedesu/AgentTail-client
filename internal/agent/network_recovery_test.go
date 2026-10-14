package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail/internal/api"
	"github.com/mizuamedesu/AgentTail/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail/internal/localstate"
	"github.com/mizuamedesu/AgentTail/internal/netdev"
	netstack "github.com/mizuamedesu/AgentTail/internal/testnet"
	"github.com/mizuamedesu/AgentTail/internal/transport"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"golang.zx2c4.com/wireguard/tun"
)

type observedTUN struct {
	tun.Device
	closed chan struct{}
	once   sync.Once
}

func (t *observedTUN) Close() error {
	err := t.Device.Close()
	t.once.Do(func() { close(t.closed) })
	return err
}

type recoveryPair struct {
	control  *testControl
	keys     [2]*Key
	mu       sync.Mutex
	networks [2]*netstack.Net
	tuns     [2]*observedTUN
}

type recoveryOptions struct {
	relay            bool
	failFirstConnect bool
	failFlow         bool
	publicRelay      bool
	configure        func(*testControl)
}

func newRecoveryPair(t *testing.T, failedRelay bool, fallbackProvider ...bool) *recoveryPair {
	t.Helper()
	failFlow := len(fallbackProvider) > 0 && fallbackProvider[0]
	return newRecoveryPairWithOptions(t, recoveryOptions{relay: failedRelay, failFlow: failFlow, failFirstConnect: failedRelay && !failFlow})
}

func newRecoveryPairWithOptions(t *testing.T, options recoveryOptions) *recoveryPair {
	t.Helper()
	c := &testControl{keys: map[string]*testEndpoint{}, sockets: map[*websocket.Conn]bool{}, ttl: 60}
	pair := &recoveryPair{control: c}
	if options.relay && !options.publicRelay {
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			udp.Close()
			t.Fatal(err)
		}
		generator := &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}
		server, err := turn.NewServer(turn.ServerConfig{Realm: "agenttail-recovery-test",
			LoggerFactory: &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled},
			AuthHandler: func(r *turn.RequestAttributes) (string, []byte, bool) {
				return r.Username, turn.GenerateAuthKey(r.Username, r.Realm, "public-test-password"), true
			},
			PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: udp, RelayAddressGenerator: generator}},
			ListenerConfigs:   []turn.ListenerConfig{{Listener: tcp, RelayAddressGenerator: generator}},
		})
		if err != nil {
			udp.Close()
			tcp.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Close() })
		c.turnServers = []transport.ICEServer{{URLs: []string{"turn:" + udp.LocalAddr().String() + "?transport=udp", "turn:" + tcp.Addr().String() + "?transport=tcp"}, Username: "public-test-user", Credential: "public-test-password"}}
		if options.failFlow {
			// The primary provider's API issues credentials, but its actual TURN
			// transport never answers. The fallback is the live local TURN server.
			unreachable, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { unreachable.Close() })
			c.flowServers = []transport.ICEServer{{URLs: []string{"turn:" + unreachable.LocalAddr().String() + "?transport=udp"}, Username: "public-flow-test-user", Credential: "public-flow-test-password"}}
		}
	}
	if options.configure != nil {
		options.configure(c)
	}
	var firstGeneration string
	var signalMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if options.failFirstConnect && r.URL.Path == "/api/agent/signal" {
			var input map[string]any
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				w.WriteHeader(400)
				return
			}
			signalMu.Lock()
			if firstGeneration == "" && input["kind"] == "offer" {
				firstGeneration = input["generation"].(string)
			}
			fail := input["generation"] == firstGeneration
			signalMu.Unlock()
			if fail {
				// Model an unusable first ICE generation; a new offer must recover
				// without weakening ICE or the control-plane authentication.
				d := input["description"].(map[string]any)
				d["ufrag"] = "unreachable-test-generation"
				d["password"] = "public-unreachable-test-password"
			}
			encoded, _ := json.Marshal(input)
			r.Body = io.NopCloser(bytes.NewReader(encoded))
			r.ContentLength = int64(len(encoded))
		}
		c.serve(w, r)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	var done [2]chan struct{}
	t.Cleanup(func() {
		cancel()
		for _, finished := range done {
			if finished != nil {
				<-finished
			}
		}
	})
	for i := range pair.keys {
		wire, err := cryptobox.GenerateWireGuard()
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)
		meta := localstate.Key{ID: id, Name: fmt.Sprintf("recovery-%d", i), Public: wire.Public, AutoUp: true}
		entry := &testEndpoint{info: KeyInfo{ID: id, Name: meta.Name, Public: wire.Public, Address: fmt.Sprintf("10.203.44.%d", i+1), CIDR: "10.203.44.0/24"}, token: "atk_public-test-" + uuid.NewString(), acks: map[string]string{}}
		c.mu.Lock()
		c.keys[id] = entry
		c.mu.Unlock()
		client, err := api.New(server.URL, entry.token, true)
		if err != nil {
			t.Fatal(err)
		}
		factory := func(_ string, private []byte, address string) (netdev.Interface, error) {
			tunDevice, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, netdev.MTU)
			if err != nil {
				return nil, err
			}
			observed := &observedTUN{Device: tunDevice, closed: make(chan struct{})}
			pair.mu.Lock()
			pair.networks[i] = network
			pair.tuns[i] = observed
			pair.mu.Unlock()
			return netdev.NewWithTUN(observed, nil, private)
		}
		key, err := NewKey(Options{Client: client, Metadata: meta, Credential: localstate.KeyCredential{KeyID: id, Public: wire.Public, Private: wire.Private, Token: entry.token}, Factory: factory,
			STUN: []transport.ICEServer{}, LoopbackOnly: !options.publicRelay, ForceRelayForTest: options.relay, RelayOnlyForTest: options.relay})
		clear(wire.Private)
		if err != nil {
			t.Fatal(err)
		}
		pair.keys[i] = key
		done[i] = make(chan struct{})
		go func() { defer close(done[i]); key.Run(ctx) }()
	}
	t.Cleanup(func() {
		if t.Failed() {
			for _, key := range pair.keys {
				t.Logf("recovery state: %+v", key.Status())
			}
			pair.mu.Lock()
			for i, n := range pair.networks {
				if n != nil {
					t.Logf("recovery stack %d: %+v", i, n.Diagnostics())
				}
			}
			pair.mu.Unlock()
		}
	})
	return pair
}

func (p *recoveryPair) connected(cidr string) bool {
	for _, key := range p.keys {
		key.RequestSync()
		s := key.Status()
		if s.CIDR != cidr || s.State != "up" || len(s.Peers) != 1 || s.Peers[0].State != "connected" {
			return false
		}
	}
	return true
}
func (p *recoveryPair) ping(target string) bool {
	p.mu.Lock()
	network := p.networks[0]
	p.mu.Unlock()
	if network == nil {
		return false
	}
	connection, err := network.DialPingAddr(netip.Addr{}, netip.MustParseAddr(target))
	if err != nil {
		return false
	}
	defer connection.Close()
	_, err = pingPacket(connection)
	return err == nil
}

func TestAgentRenumbersPrivateNetwork(t *testing.T) {
	pair := newRecoveryPair(t, false)
	waitFor(t, 10*time.Second, "initial private VPN", func() bool { return pair.connected("10.203.44.0/24") })
	waitFor(t, 10*time.Second, "initial encrypted ping", func() bool { return pair.ping("10.203.44.2") })
	pair.mu.Lock()
	oldTUNs := pair.tuns
	pair.mu.Unlock()
	pair.control.mu.Lock()
	for i, key := range pair.keys {
		entry := pair.control.keys[key.id]
		entry.info.Address = fmt.Sprintf("172.27.9.%d", i+1)
		entry.info.CIDR = "172.27.9.0/24"
		entry.signals = nil
	}
	pair.control.mu.Unlock()
	pair.control.notify("vpn.network_changed", "")
	waitFor(t, 10*time.Second, "renumbered private VPN", func() bool { return pair.connected("172.27.9.0/24") })
	for _, old := range oldTUNs {
		select {
		case <-old.closed:
		default:
			t.Fatal("old VPN interface was left open")
		}
	}
	waitFor(t, 10*time.Second, "encrypted ping after renumbering", func() bool { return pair.ping("172.27.9.2") })
}

func TestFailedRelayRetriesWithTCP(t *testing.T) {
	pair := newRecoveryPair(t, true)
	// Use the production attempt budget: each side may spend up to eight
	// seconds gathering, followed by a failed connect and the retry backoff.
	waitFor(t, 60*time.Second, "relay recovery", func() bool { return pair.connected("10.203.44.0/24") })
	pair.keys[0].mu.Lock()
	p := pair.keys[0].peers[pair.keys[1].id]
	recovered := p != nil && p.relayTCP && p.active != nil && p.active.ice.Stats().Relay
	pair.keys[0].mu.Unlock()
	if !recovered {
		t.Fatal("failed relay did not recover using the TCP fallback")
	}
	waitFor(t, 10*time.Second, "encrypted ping through recovered relay", func() bool { return pair.ping("10.203.44.2") })
}

func TestFlowTransportFailureFallsBackToCloudflare(t *testing.T) {
	pair := newRecoveryPair(t, true, true)
	waitFor(t, 45*time.Second, "provider fallback", func() bool { return pair.connected("10.203.44.0/24") })
	for _, key := range pair.keys {
		key.mu.Lock()
		for _, peer := range key.peers {
			if peer.active == nil || peer.active.credential == nil || peer.active.credential.provider != "cloudflare" || !peer.active.ice.Stats().Relay {
				key.mu.Unlock()
				t.Fatal("fallback did not establish a real relayed connection on both endpoints")
			}
		}
		key.mu.Unlock()
	}
	pair.control.mu.Lock()
	providers := append([]string(nil), pair.control.turnProviders...)
	pair.control.mu.Unlock()
	if len(providers) < 3 || providers[0] != "flow" || providers[len(providers)-1] != "cloudflare" {
		t.Fatalf("unexpected provider request order: %v", providers)
	}
	waitFor(t, 10*time.Second, "encrypted ping after provider fallback", func() bool { return pair.ping("10.203.44.2") })
}
