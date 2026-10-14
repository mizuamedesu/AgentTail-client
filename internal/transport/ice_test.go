// SPDX-License-Identifier: GPL-3.0-or-later

package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func TestTCPRelayFallbackAndUDPOnlyProvider(t *testing.T) {
	for _, udpOnly := range []bool{false, true} {
		name := "tcp-fallback"
		if udpOnly {
			name = "udp-only-provider"
		}
		t.Run(name, func(t *testing.T) {
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
			server, err := turn.NewServer(turn.ServerConfig{Realm: "agenttail-tcp-test",
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
			defer server.Close()
			urls := []string{"turn:" + udp.LocalAddr().String() + "?transport=udp"}
			if !udpOnly {
				urls = append(urls, "turn:"+tcp.Addr().String()+"?transport=tcp")
			}
			options := ICEOptions{LoopbackOnly: true, RelayTCPFallback: true, RelayOnly: udpOnly, Servers: []ICEServer{{URLs: urls, Username: "public-test-user", Credential: "public-test-password"}}}
			var peers [2]*ICE
			var descriptions [2]Description
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for i := range peers {
				peers[i], err = NewICE(options)
				if err != nil {
					t.Fatal(err)
				}
				defer peers[i].Close()
				descriptions[i], err = peers[i].Gather(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, candidate := range peers[i].agent.GetLocalCandidatesStats() {
					want := "tcp"
					if udpOnly {
						want = "udp"
					}
					if candidate.CandidateType != ice.CandidateTypeRelay || candidate.RelayProtocol != want {
						t.Fatalf("fallback selected %s over %s", candidate.CandidateType, candidate.RelayProtocol)
					}
				}
			}
			connected := make(chan error, 2)
			go func() { connected <- peers[0].Connect(ctx, descriptions[1], true) }()
			go func() { connected <- peers[1].Connect(ctx, descriptions[0], false) }()
			for range 2 {
				if err := <-connected; err != nil {
					t.Fatal(err)
				}
			}
			payload := []byte("relay fallback fixture")
			received := make(chan []byte, 1)
			go func() { b := make([]byte, 128); n, _ := peers[1].Read(b); received <- b[:n] }()
			if _, err := peers[0].Write(payload); err != nil {
				t.Fatal(err)
			}
			select {
			case actual := <-received:
				if !bytes.Equal(payload, actual) {
					t.Fatal("relay payload changed")
				}
			case <-ctx.Done():
				t.Fatal("relay payload did not arrive")
			}
		})
	}
}

func TestConnectPreservesDeadline(t *testing.T) {
	peer, err := NewICE(ICEOptions{LoopbackOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = peer.Gather(ctx); err != nil {
		t.Fatal(err)
	}
	remote := Description{Ufrag: "public-test-peer", Password: "public-test-password-for-ice", Candidates: []string{"1 1 udp 1 127.0.0.1 9 typ host"}}
	if err = peer.Connect(ctx, remote, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost connection deadline: %v", err)
	}
}

func TestGatherDeadlineKeepsUsableRelay(t *testing.T) {
	// A reachable TURN server and an unresponsive one must not prevent the
	// reachable allocation from being advertised to the other device.
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm:         "agenttail-gather-test",
		LoggerFactory: &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled},
		AuthHandler: func(request *turn.RequestAttributes) (string, []byte, bool) {
			return request.Username, turn.GenerateAuthKey(request.Username, request.Realm, "public-test-password"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: listener, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}}},
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	defer server.Close()
	silent := silentICEEndpoint(t)
	options := ICEOptions{LoopbackOnly: true, RelayOnly: true, Servers: []ICEServer{{
		URLs:     []string{"turn:" + listener.LocalAddr().String() + "?transport=udp", "turn:" + silent + "?transport=udp"},
		Username: "public-test-user", Credential: "public-test-password",
	}}}
	first, err := NewICE(options)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	description, err := first.Gather(ctx)
	if err != nil {
		t.Fatalf("usable relay was discarded at the gathering deadline: %v", err)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("test did not exercise an incomplete gather")
	}
	for _, raw := range description.Candidates {
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil || candidate.Type() != ice.CandidateTypeRelay {
			t.Fatal("relay-only gathering returned a non-relay candidate")
		}
	}
	// The partial description must remain usable after Gather's context ends.
	options.Servers[0].URLs = options.Servers[0].URLs[:1]
	second, err := NewICE(options)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	connectionCtx, stop := context.WithTimeout(context.Background(), 8*time.Second)
	defer stop()
	answer, err := second.Gather(connectionCtx)
	if err != nil {
		t.Fatal(err)
	}
	connected := make(chan error, 2)
	go func() { connected <- first.Connect(connectionCtx, answer, true) }()
	go func() { connected <- second.Connect(connectionCtx, description, false) }()
	for range 2 {
		if err := <-connected; err != nil {
			t.Fatal(err)
		}
	}
	if !first.Stats().Relay || !second.Stats().Relay {
		t.Fatal("expected a real TURN connection")
	}
}

func TestGatherDeadlineWithoutCandidatesFails(t *testing.T) {
	silent := silentICEEndpoint(t)
	connection, err := NewICE(ICEOptions{LoopbackOnly: true, RelayOnly: true, Servers: []ICEServer{{
		URLs: []string{"turn:" + silent + "?transport=udp"}, Username: "public-test-user", Credential: "public-test-password",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := connection.Gather(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("gathering without candidates must preserve the deadline error, got %v", err)
	}
}

func TestGatherCancellationDiscardsPartialCandidates(t *testing.T) {
	silent := silentICEEndpoint(t)
	connection, err := NewICE(ICEOptions{LoopbackOnly: true, Servers: []ICEServer{{URLs: []string{"stun:" + silent}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := connection.Gather(ctx); result <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		candidates, err := connection.agent.GetLocalCandidates()
		if err != nil {
			t.Fatal(err)
		}
		if len(candidates) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("local candidates were not gathered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("explicit cancellation must discard partial candidates, got %v", err)
	}
}

func silentICEEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			if _, _, err := listener.ReadFrom(buffer); err != nil {
				return
			}
		}
	}()
	return listener.LocalAddr().String()
}
