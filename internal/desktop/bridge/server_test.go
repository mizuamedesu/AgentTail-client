// SPDX-License-Identifier: GPL-3.0-or-later

package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mizuamedesu/AgentTail-client/internal/desktop"
)

type fixture struct {
	mu       sync.Mutex
	snapshot desktop.Snapshot
	actions  []desktop.Action
}

func (f *fixture) Status(context.Context) (desktop.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.snapshot
	s.VPNs = append([]desktop.VPN{}, s.VPNs...)
	return s, nil
}
func (f *fixture) Toggle(_ context.Context, a desktop.Action) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, v := range f.snapshot.VPNs {
		if v.ID == a.ID {
			if a.Action == "leave" {
				f.snapshot.VPNs = append(f.snapshot.VPNs[:i], f.snapshot.VPNs[i+1:]...)
				f.actions = append(f.actions, a)
				return nil
			}
			f.snapshot.VPNs[i].Desired = a.Action
			f.actions = append(f.actions, a)
			return nil
		}
	}
	return errors.New("VPN not installed")
}
func (f *fixture) StartService(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshot.Running = true
	return nil
}

func setup(t *testing.T) (*Server, *httptest.Server, *fixture) {
	t.Helper()
	f := &fixture{snapshot: desktop.Snapshot{Version: "0.1.0-test", Running: true, VPNs: []desktop.VPN{{ID: "00000000-0000-4000-8000-000000000001", Name: "研究 <VPN>", Desired: "up"}, {ID: "00000000-0000-4000-8000-000000000002", Name: "Other VPN", Desired: "down"}}}}
	s := &Server{Backend: f}
	h := httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	s.Session = desktop.Session{Port: h.Listener.Addr().(*net.TCPAddr).Port, Secret: strings.Repeat("s", 43), Version: f.snapshot.Version}
	h.Start()
	t.Cleanup(h.Close)
	return s, h, f
}

func TestIndependentVPNsAndNoCredentialExport(t *testing.T) {
	s, _, _ := setup(t)
	c := desktop.NewClient(s.Session)
	ctx := context.Background()
	if err := c.Toggle(ctx, "00000000-0000-4000-8000-000000000001", "down"); err != nil {
		t.Fatal(err)
	}
	state, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.VPNs[0].Desired != "down" || state.VPNs[1].Desired != "down" {
		t.Fatalf("other VPN changed: %+v", state.VPNs)
	}
	if err := c.Toggle(ctx, "00000000-0000-4000-8000-000000000002", "up"); err != nil {
		t.Fatal(err)
	}
	state, err = c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.VPNs[0].Desired != "down" || state.VPNs[1].Desired != "up" {
		t.Fatalf("other VPN changed: %+v", state.VPNs)
	}
	if err := c.Toggle(ctx, "00000000-0000-4000-8000-000000000003", "up"); err == nil {
		t.Fatal("foreign key was accepted")
	}
	if err := c.Toggle(ctx, state.VPNs[0].ID, "revoke"); err == nil {
		t.Fatal("operation outside the GUI scope was accepted")
	}
	encoded, _ := json.Marshal(state)
	for _, field := range []string{"private_key", "credential", "public_key", "grant_id", "instance_id", "session", "secret"} {
		if bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("GUI status exposes %q", field)
		}
	}
}

func TestDesktopAuthorizationAndBrowserIsolation(t *testing.T) {
	s, h, f := setup(t)
	for _, tc := range []struct {
		name, token, host, origin, site, path, body string
		want                                        int
	}{
		{name: "missing capability", path: "/v1/status", want: 403},
		{name: "incorrect capability", token: "wrong", path: "/v1/status", want: 403},
		{name: "foreign origin", token: s.Session.Secret, origin: "https://example.com", path: "/v1/status", want: 403},
		{name: "browser fetch", token: s.Session.Secret, site: "same-origin", path: "/v1/status", want: 403},
		{name: "rebound host", token: s.Session.Secret, host: "example.com", path: "/v1/status", want: 403},
		{name: "arbitrary command", token: s.Session.Secret, path: "/v1/exec", body: `{"command":"whoami"}`, want: 404},
		{name: "scope expansion", token: s.Session.Secret, path: "/v1/vpn", body: `{"id":"00000000-0000-4000-8000-000000000001","action":"down","command":"whoami"}`, want: 400},
		{name: "trailing command", token: s.Session.Secret, path: "/v1/vpn", body: `{"id":"00000000-0000-4000-8000-000000000001","action":"down"}{}`, want: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := "GET"
			if tc.body != "" {
				method = "POST"
			}
			r, _ := http.NewRequest(method, h.URL+tc.path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer "+tc.token)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			if tc.host != "" {
				r.Host = tc.host
			}
			response, err := h.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, response.Body)
			if response.StatusCode != tc.want {
				t.Fatalf("got %d, want %d", response.StatusCode, tc.want)
			}
			if response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("desktop response can be cached")
			}
		})
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.actions) != 0 {
		t.Fatal("rejected request reached VPN controls")
	}
}

func TestRemovalAffectsOnlyTheSelectedVPN(t *testing.T) {
	s, _, _ := setup(t)
	c := desktop.NewClient(s.Session)
	ctx := context.Background()
	if err := c.Remove(ctx, "00000000-0000-4000-8000-000000000002"); err != nil {
		t.Fatal(err)
	}
	state, err := c.Status(ctx)
	if err != nil || len(state.VPNs) != 1 || state.VPNs[0].ID != "00000000-0000-4000-8000-000000000001" || state.VPNs[0].Desired != "up" {
		t.Fatal("removal changed the other VPN", state, err)
	}
	if err := c.Remove(ctx, "00000000-0000-4000-8000-000000000003"); err == nil {
		t.Fatal("a foreign VPN could be removed")
	}
}
