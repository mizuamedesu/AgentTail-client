// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/netdev"
	netstack "github.com/mizuamedesu/AgentTail-client/internal/netstack"
	"github.com/mizuamedesu/AgentTail-client/internal/transport"
)

func TestActivationFailureClassificationAndRecovery(t *testing.T) {
	for _, failure := range []string{"control", "configuration", "interface"} {
		t.Run(failure, func(t *testing.T) {
			pair, err := cryptobox.GenerateWireGuard()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(pair.Private)
			meta := localstate.Key{ID: uuid.NewString(), Name: "test-vpn", Public: pair.Public, AutoUp: true}
			entry := &testEndpoint{info: KeyInfo{ID: meta.ID, Name: meta.Name, Public: meta.Public, Address: "100.126.251.1"}, token: "atk_public-test-" + uuid.NewString(), acks: map[string]string{}}
			control := &testControl{keys: map[string]*testEndpoint{meta.ID: entry}, sockets: map[*websocket.Conn]bool{}, ttl: 60}
			var interfaceFailed atomic.Bool
			wantProblem := "CONFIGURATION"
			switch failure {
			case "control":
				control.fail = true
				wantProblem = "NETWORK"
			case "configuration":
				entry.info.Public = "wrong-key-scope"
			case "interface":
				interfaceFailed.Store(true)
			}
			server := httptest.NewServer(http.HandlerFunc(control.serve))
			defer server.Close()
			client, err := api.New(server.URL, entry.token, true)
			if err != nil {
				t.Fatal(err)
			}
			factory := func(_ string, private []byte, ip string) (netdev.Interface, error) {
				if interfaceFailed.Load() {
					return nil, errors.New("synthetic interface failure")
				}
				tun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(ip)}, nil, netdev.MTU)
				if err != nil {
					return nil, err
				}
				return netdev.NewWithTUN(tun, nil, private)
			}
			key, err := NewKey(Options{Client: client, Metadata: meta,
				Credential: localstate.KeyCredential{KeyID: meta.ID, Public: meta.Public, Private: pair.Private, Token: entry.token},
				Factory:    factory, STUN: []transport.ICEServer{}, DisableEvents: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); key.Run(ctx) }()
			defer func() { cancel(); <-done }()
			waitFor(t, 5*time.Second, "classified activation failure", func() bool { return key.Status().Problem == wantProblem })
			status := key.Status()
			if status.State != "error" || status.Authorized || status.Desired != "up" || status.Interface != "" {
				t.Fatalf("failed activation must keep retry intent with a closed data gate: %+v", status)
			}
			control.mu.Lock()
			control.fail = false
			entry.info.Public = meta.Public
			control.mu.Unlock()
			interfaceFailed.Store(false)
			key.RequestSync()
			waitFor(t, 5*time.Second, "activation recovery without a new grant", func() bool { return key.Status().State == "up" })
			status = key.Status()
			if !status.Authorized || status.Problem != "" || status.Desired != "up" {
				t.Fatalf("recovered activation retained a stale error: %+v", status)
			}
		})
	}
}
