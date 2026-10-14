package poc

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail/internal/transport"
	"github.com/pion/turn/v5"
)

func TestDirectWireGuardPingAndSSH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := Run(ctx, Config{LoopbackOnly: true, PingCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != "direct" || len(report.PingMS) != 2 || !strings.Contains(report.SSH, "authenticated SSH") {
		t.Fatalf("unexpected result: %+v", report)
	}
	for _, s := range report.Stats {
		if s.Sent == 0 || s.Received == 0 {
			t.Fatal("no encrypted traffic measured")
		}
	}
}

func TestTURNRelayWireGuardPingAndSSH(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "agenttail-test",
		AuthHandler: func(request *turn.RequestAttributes) (string, []byte, bool) {
			if request.Username != "test-peer" {
				return "", nil, false
			}
			return request.Username, turn.GenerateAuthKey(request.Username, request.Realm, "local-test-password"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: listener, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}}},
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	defer server.Close()
	iceServers := []transport.ICEServer{{URLs: []string{"turn:" + listener.LocalAddr().String() + "?transport=udp"}, Username: "test-peer", Credential: "local-test-password"}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := Run(ctx, Config{LoopbackOnly: true, RelayOnly: true, Peers: [2][]transport.ICEServer{iceServers, iceServers}, PingCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != "relay" || report.LocalCandidate != "relay" || report.RemoteCandidate != "relay" || !strings.Contains(report.SSH, "authenticated SSH") {
		t.Fatalf("relay not proved: %+v", report)
	}
}
