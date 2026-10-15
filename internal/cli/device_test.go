// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail-client/internal/agent"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/netdev"
)

func TestDeviceAuthorizationProbe(t *testing.T) {
	key := localstate.Key{ID: uuid.NewString(), VPNID: uuid.NewString(), GrantID: uuid.NewString(), Public: "fixture-public"}
	identity := map[string]any{"key_id": key.ID, "vpn_id": key.VPNID, "grant_id": key.GrantID, "public_key": key.Public, "expires_at": time.Now().Add(time.Hour).Unix()}
	for _, test := range []struct {
		name                string
		status              int
		body                any
		authorized, wantErr bool
	}{
		{"active", 200, map[string]any{"ok": true, "data": identity}, true, false},
		{"revoked", 401, map[string]any{"ok": false, "error": api.Error{Code: "UNAUTHENTICATED"}}, false, false},
		{"forbidden", 403, map[string]any{"ok": false, "error": api.Error{Code: "FORBIDDEN"}}, false, true},
		{"server failure", 503, map[string]any{"ok": false, "error": api.Error{Code: "UNAUTHENTICATED"}}, false, true},
		{"older server", 404, map[string]any{"ok": false, "error": api.Error{Code: "NOT_FOUND"}}, false, true},
		{"wrong status", 200, map[string]any{"ok": false, "error": api.Error{Code: "UNAUTHENTICATED"}}, false, true},
		{"wrong identity", 200, map[string]any{"ok": true, "data": map[string]any{"key_id": uuid.NewString()}}, false, true},
		{"invalid response", 200, "not an API envelope", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/agent/identity" || r.Header.Get("Authorization") != "Bearer test-credential" {
					t.Error("unexpected identity request")
				}
				w.WriteHeader(test.status)
				json.NewEncoder(w).Encode(test.body)
			}))
			defer server.Close()
			client, err := api.New(server.URL, "test-credential", true)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := deviceAuthorized(context.Background(), client, key)
			if valid != test.authorized || (err != nil) != test.wantErr {
				t.Fatalf("authorized=%v, error=%v", valid, err)
			}
		})
	}
	client, _ := api.New("http://127.0.0.1:1", "test-credential", true)
	if valid, err := deviceAuthorized(context.Background(), client, key); valid || err == nil {
		t.Fatal("network failure must not prove revocation")
	}
	o := options{server: "https://different.example.test", config: localstate.Config{Server: "https://original.example.test", Keys: []localstate.Key{key}}}
	if _, err := o.prepareVPNJoin(key.VPNID); err == nil {
		t.Fatal("different server must be rejected before accessing credentials")
	}
}

func TestNativeVPNJoinRecovery(t *testing.T) {
	if os.Getenv("AGENTTAIL_TEST_NATIVE_SECRETS") != "1" && !(runtime.GOOS == "linux" && runtime.GOARCH == "riscv64" && os.Geteuid() == 0) {
		t.Skip("explicit opt-in required for native credential storage")
	}
	for _, status := range []int{200, 401, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			state, err := localstate.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var keys []localstate.Key
			for _, name := range []string{"rejoin", "other-vpn"} {
				private, err := cryptobox.Random(32)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(private)
				public, err := cryptobox.PublicFromPrivate(private)
				if err != nil {
					t.Fatal(err)
				}
				key := localstate.Key{ID: uuid.NewString(), VPNID: uuid.NewString(), GrantID: uuid.NewString(), Name: name, Public: public, AutoUp: true, Expires: time.Now().Add(time.Hour).Unix()}
				credential := localstate.KeyCredential{KeyID: key.ID, Public: public, Private: private, Token: "atk_" + strings.Repeat("a", 43), Expires: key.Expires}
				if err := state.Store.Put("key/"+key.ID, credential); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { state.Store.Delete("key/" + key.ID) })
				keys = append(keys, key)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/agent/identity" {
					t.Error("join must not revoke or re-register an active credential")
				}
				w.WriteHeader(status)
				if status == 200 {
					json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{"key_id": keys[0].ID, "vpn_id": keys[0].VPNID, "grant_id": keys[0].GrantID, "public_key": keys[0].Public, "expires_at": keys[0].Expires}})
				} else {
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": api.Error{Code: "UNAUTHENTICATED"}})
				}
			}))
			defer server.Close()
			if err = state.Update(func(c *localstate.Config) error { c.Server = server.URL; c.Keys = keys; return nil }); err != nil {
				t.Fatal(err)
			}
			config, err := state.Read()
			if err != nil {
				t.Fatal(err)
			}
			o := options{ctx: context.Background(), state: state, config: config, server: server.URL, local: true}
			joined, err := o.prepareVPNJoin(keys[0].VPNID)
			if (err != nil) != (status == 503) {
				t.Fatalf("unexpected recovery result: %v", err)
			}
			if (joined != nil) != (status == 200) {
				t.Fatal("unexpected reuse of local identity")
			}
			current, err := state.Read()
			if err != nil {
				t.Fatal(err)
			}
			wanted := keys
			if status == 401 {
				wanted = keys[1:]
			}
			if !reflect.DeepEqual(current.Keys, wanted) {
				t.Fatal("rejoin changed an unrelated or still-authorized VPN")
			}
			for i, key := range keys {
				credential, err := state.LoadKey(key)
				clear(credential.Private)
				if status == 401 && i == 0 {
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatal("revoked native credential was not removed")
					}
				} else if err != nil {
					t.Fatal("unrelated or valid native credential was lost", err)
				}
			}
		})
	}
	t.Run("userspace mode and service restart preserve approval", testNativeUserspaceRestart)
	t.Run("desktop removes only the selected VPN", testNativeDesktopRemoval)
}

func testNativeUserspaceRestart(t *testing.T) {
	state, err := localstate.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyPair, err := cryptobox.GenerateWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyPair.Private)
	key := localstate.Key{ID: uuid.NewString(), VPNID: uuid.NewString(), GrantID: uuid.NewString(), Name: "userspace-restart", Public: keyPair.Public, Expires: time.Now().Add(time.Hour).Unix()}
	credential := localstate.KeyCredential{KeyID: key.ID, Public: key.Public, Private: keyPair.Private, Token: "atk_" + strings.Repeat("b", 43), Expires: key.Expires}
	if err := state.Store.Put("key/"+key.ID, credential); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Store.Delete("key/" + key.ID) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential.Token {
			t.Error("userspace mode changed device credential")
			w.WriteHeader(403)
			return
		}
		var output any
		switch r.URL.Path {
		case "/api/agent/lease":
			var input map[string]any
			json.NewDecoder(r.Body).Decode(&input)
			output = map[string]any{"key_id": key.ID, "instance_id": input["instance_id"], "ttl_seconds": 60}
		case "/api/agent/sync":
			instance := r.URL.Query().Get("instance_id")
			output = map[string]any{"key": map[string]any{"key_id": key.ID, "vpn_id": key.VPNID, "public_key": key.Public, "name": key.Name, "virtual_ip": "100.126.251.17"}, "instance_id": instance, "desired_state": "up", "limits": map[string]int{"max_connections": 10, "bytes_per_second": 1250000}, "peers": []any{}, "signals": []any{}, "commands": []any{}, "lease_remaining_seconds": 60}
		default:
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": output})
	}))
	defer server.Close()
	if err := state.Update(func(c *localstate.Config) error {
		c.Server = server.URL
		c.AllowLocalHTTP = true
		c.Keys = []localstate.Key{key}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	reservation.Close()
	settings := netdev.Settings{Mode: "userspace", SOCKS5: address}
	o := &options{ctx: context.Background(), state: state, server: server.URL, network: &settings, json: true}
	if err := o.saveNetwork(key.ID); err != nil {
		t.Fatal(err)
	}
	start := func() func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- agent.Serve(ctx, state) }()
		stop := func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		return stop
	}
	status := func() agent.Status {
		var output struct {
			Keys []agent.Status `json:"keys"`
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if agent.LocalRequest(ctx, state.Store.Dir, key.ID, "status", &output) != nil || len(output.Keys) != 1 {
			return agent.Status{}
		}
		return output.Keys[0]
	}
	wait := func(check func(agent.Status) bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if check(status()) {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("userspace manager did not reach expected state: %+v", status())
	}
	stop := start()
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	wait(func(s agent.Status) bool { return s.ID == key.ID })
	if err := o.requestNetwork("up", key.ID, key.Name); err != nil {
		t.Fatal(err)
	}
	wait(func(s agent.Status) bool {
		return s.State == "up" && s.NetworkMode == "userspace" && s.SOCKS5 == address
	})
	if err := agent.LocalRequest(o.ctx, state.Store.Dir, key.ID, "down", nil); err != nil {
		t.Fatal(err)
	}
	settings = netdev.Settings{Mode: "native"}
	if err := o.saveNetwork(key.ID); err != nil {
		t.Fatal(err)
	}
	if err := agent.LocalRequest(o.ctx, state.Store.Dir, key.ID, "sync", nil); err != nil {
		t.Fatal(err)
	}
	wait(func(s agent.Status) bool { return s.NetworkMode == "native" && s.Desired == "down" && s.SOCKS5 == "" })
	settings = netdev.Settings{Mode: "userspace", SOCKS5: address}
	if err := o.requestNetwork("up", key.ID, key.Name); err != nil {
		t.Fatal(err)
	}
	stop()
	stop = nil
	if c, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		c.Close()
		t.Fatal("stopped manager retained the proxy")
	}
	stop = start()
	wait(func(s agent.Status) bool { return s.State == "up" && s.Authorized && s.SOCKS5 == address })
	config, err := state.Read()
	if err != nil || len(config.Keys) != 1 || config.Keys[0].Network != settings || !config.Keys[0].AutoUp || config.Keys[0].GrantID != key.GrantID {
		t.Fatalf("mode change or restart lost local metadata: %+v, %v", config, err)
	}
	stored, err := state.LoadKey(key)
	defer clear(stored.Private)
	if err != nil || !reflect.DeepEqual(stored, credential) {
		t.Fatal("mode change or restart replaced the approved credential", err)
	}
}
