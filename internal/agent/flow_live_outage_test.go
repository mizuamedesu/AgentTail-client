// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/transport"
	"github.com/pion/stun/v4"
)

// Opt-in only: a separate operator process obtains and rotates the short-lived
// credentials in a mode-0600 file. No provider/API secrets belong in CI or logs.
// The local TCP proxy cuts only these test agents off from the real Flow relay.
func TestLiveEstablishedFlowOutageFallsBackToCloudflare(t *testing.T) {
	path := os.Getenv("AGENTTAIL_LIVE_RELAY_CREDENTIALS")
	if path == "" {
		t.Skip("live provider credentials were not supplied")
	}
	initial, err := readOutageCredentials(path)
	if err != nil {
		t.Fatal("live credential fixture unavailable")
	}
	var upstream string
	for _, server := range initial["flow"].Servers {
		for _, raw := range server.URLs {
			uri, err := stun.ParseURI(raw)
			if err == nil && uri.Scheme == stun.SchemeTypeTURN && uri.Proto == stun.ProtoTypeTCP {
				upstream = net.JoinHostPort(uri.Host, strconv.Itoa(uri.Port))
				break
			}
		}
		if upstream != "" {
			break
		}
	}
	if upstream == "" {
		t.Fatal("Flow did not advertise TCP TURN")
	}
	proxyURL, stopFlow := outageTCPProxy(t, upstream)
	verifyEstablishedFlowOutage(t, recoveryOptions{relay: true, publicRelay: true, configure: func(c *testControl) {
		c.turnProvider = func(preferred string) ([]transport.ICEServer, string, int, error) {
			provider := "flow"
			if preferred == "cloudflare" {
				provider = "cloudflare"
			}
			credentials, err := readOutageCredentials(path)
			if err != nil {
				return nil, provider, 0, err
			}
			value := credentials[provider]
			ttl := int(value.ExpiresAt - time.Now().Unix())
			if ttl < 20 || ttl > 60 || len(value.Servers) == 0 {
				return nil, provider, 0, errors.New("live relay credentials are not usable")
			}
			if provider == "flow" {
				// Flow emits one authenticated TURN server entry. Restrict that
				// entry to the proxy so every primary data path can be interrupted.
				server := value.Servers[0]
				server.URLs = []string{proxyURL}
				value.Servers = []transport.ICEServer{server}
			}
			return value.Servers, provider, ttl, nil
		}
	}}, stopFlow, "two agents on one host; real HeteroCloud Flow and Cloudflare TURN; established Flow TCP transport cut at a test-only local proxy; mocked control/signaling API with real short-lived provider credentials; production services remain running")
}

type outageCredential struct {
	Servers   []transport.ICEServer `json:"iceServers"`
	ExpiresAt int64                 `json:"expires_at"`
}

func readOutageCredentials(path string) (map[string]outageCredential, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("live credential fixture must be private")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var result map[string]outageCredential
	err = json.Unmarshal(data, &result)
	return result, err
}

func outageTCPProxy(t *testing.T, upstream string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var once sync.Once
	var work sync.WaitGroup
	connections := map[net.Conn]bool{}
	stopped := false
	work.Add(1)
	go func() {
		defer work.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if stopped {
				mu.Unlock()
				client.Close()
				return
			}
			connections[client] = true
			work.Add(1)
			mu.Unlock()
			go func() {
				defer work.Done()
				defer client.Close()
				defer func() { mu.Lock(); delete(connections, client); mu.Unlock() }()
				remote, err := net.DialTimeout("tcp", upstream, 5*time.Second)
				if err != nil {
					return
				}
				defer remote.Close()
				mu.Lock()
				if stopped {
					mu.Unlock()
					return
				}
				connections[remote] = true
				mu.Unlock()
				defer func() { mu.Lock(); delete(connections, remote); mu.Unlock() }()
				done := make(chan struct{})
				go func() { io.Copy(remote, client); remote.Close(); close(done) }()
				io.Copy(client, remote)
				client.Close()
				<-done
			}()
		}
	}()
	stop := func() {
		once.Do(func() {
			mu.Lock()
			stopped = true
			listener.Close()
			for conn := range connections {
				conn.Close()
			}
			mu.Unlock()
			work.Wait()
		})
	}
	t.Cleanup(stop)
	return "turn:" + listener.Addr().String() + "?transport=tcp", stop
}
