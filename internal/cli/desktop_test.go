// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/desktop"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
)

// Called by the existing native-credential gate on each supported OS. Every
// credential and configuration belongs to this temporary fixture, never a user.
func testNativeDesktopRemoval(t *testing.T) {
	for _, status := range []int{200, 401, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			state, err := localstate.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var keys []localstate.Key
			for _, name := range []string{"selected", "other VPN"} {
				pair, err := cryptobox.GenerateWireGuard()
				if err != nil {
					t.Fatal(err)
				}
				key := localstate.Key{ID: uuid.NewString(), VPNID: uuid.NewString(), GrantID: uuid.NewString(), Name: name, Public: pair.Public, AutoUp: true, Expires: time.Now().Add(time.Hour).Unix()}
				credential := localstate.KeyCredential{KeyID: key.ID, Public: key.Public, Private: pair.Private, Token: "atk_" + strings.Repeat(string(rune('a'+len(keys))), 43), Expires: key.Expires}
				err = state.Store.Put("key/"+key.ID, credential)
				clear(pair.Private)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { state.Store.Delete("key/" + key.ID) })
				keys = append(keys, key)
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "POST" || r.URL.Path != "/api/agent/logout" || r.Header.Get("Authorization") != "Bearer atk_"+strings.Repeat("a", 43) {
					t.Error("desktop removal used an unexpected API operation")
				}
				w.WriteHeader(status)
				if status == 200 {
					json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]bool{"revoked": true}})
				} else {
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": api.Error{Code: "UNAUTHENTICATED"}})
				}
			}))
			defer server.Close()
			if err = state.Update(func(c *localstate.Config) error { c.Server = server.URL; c.Keys = keys; return nil }); err != nil {
				t.Fatal(err)
			}
			backend := desktopBackend{state: state, version: "test", local: true}
			ctx := context.Background()
			if err = backend.Toggle(ctx, desktop.Action{ID: uuid.NewString(), Action: "leave"}); err == nil || requests.Load() != 0 {
				t.Fatal("foreign VPN reached the revocation API")
			}
			err = backend.Toggle(ctx, desktop.Action{ID: keys[0].ID, Action: "leave"})
			if (err != nil) != (status == 503) || requests.Load() != 1 {
				t.Fatal("unexpected removal result", err, requests.Load())
			}
			config, err := state.Read()
			if err != nil {
				t.Fatal(err)
			}
			expected := 1
			if status == 503 {
				expected = 2
			}
			if len(config.Keys) != expected || config.Keys[len(config.Keys)-1] != keys[1] {
				t.Fatal("removal changed an unrelated VPN or lost the retryable registration")
			}
			for i, key := range keys {
				credential, err := state.LoadKey(key)
				clear(credential.Private)
				if i == 0 && status != 503 {
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatal("revoked VPN credential was not removed", err)
					}
				} else if err != nil {
					t.Fatal("an unrelated or retryable credential was removed", err)
				}
			}
		})
	}
}
