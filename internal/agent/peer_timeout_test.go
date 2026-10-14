package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
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
)

func TestUnansweredDirectOfferFallsBackToRelay(t *testing.T) {
	pair, err := cryptobox.GenerateWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pair.Private)
	remote, err := cryptobox.GenerateWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(remote.Private)
	// The peer keeps its lease but never answers an offer, as can happen when
	// its candidate gathering fails. The next attempt must request TURN.
	meta := localstate.Key{ID: "00000000-0000-4000-8000-000000000001", Public: pair.Public, Name: "timeout-test", AutoUp: true}
	entry := &testEndpoint{info: KeyInfo{ID: meta.ID, Name: meta.Name, Public: pair.Public, Address: "100.126.251.1"}, token: "atk_public-test-" + uuid.NewString(), acks: map[string]string{}}
	peer := &testEndpoint{info: KeyInfo{ID: "00000000-0000-4000-8000-000000000002", Name: "silent-peer", Public: remote.Public, Address: "100.126.251.2", Instance: uuid.NewString()}, expires: time.Now().Add(time.Hour), desired: "up"}
	control := &testControl{keys: map[string]*testEndpoint{meta.ID: entry, peer.info.ID: peer}, sockets: map[*websocket.Conn]bool{}, ttl: 60}
	var turnRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/turn" {
			turnRequests.Add(1)
		}
		control.serve(w, r)
	}))
	defer server.Close()
	client, err := api.New(server.URL, entry.token, true)
	if err != nil {
		t.Fatal(err)
	}
	factory := func(_ string, private []byte, ip string) (netdev.Interface, error) {
		tun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(ip)}, nil, netdev.MTU)
		if err != nil {
			return nil, err
		}
		return netdev.NewWithTUN(tun, nil, private)
	}
	key, err := NewKey(Options{Client: client, Metadata: meta,
		Credential: localstate.KeyCredential{KeyID: meta.ID, Public: meta.Public, Private: pair.Private, Token: entry.token},
		Factory:    factory, STUN: []transport.ICEServer{}, LoopbackOnly: true, DisableEvents: true, AttemptTimeoutForTest: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); key.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, 5*time.Second, "safe diagnostic for an unanswered offer", func() bool {
		status := key.Status()
		return len(status.Peers) == 1 && status.Peers[0].Problem == "ANSWER_TIMEOUT"
	})
	waitFor(t, 9*time.Second, "TURN request after an unanswered direct offer", func() bool {
		key.RequestSync()
		return turnRequests.Load() > 0
	})
}
