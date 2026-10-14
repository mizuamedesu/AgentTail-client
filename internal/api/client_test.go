// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerAndRedirectBoundary(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?token=x", "file:///tmp/x"} {
		if _, err := New(origin, "secret", true); err == nil {
			t.Fatalf("accepted unsafe origin %q", origin)
		}
	}
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL+"/api/leak", 302) }))
	defer source.Close()
	c, err := New(source.URL, "secret", true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Do(context.Background(), "GET", "/api/status", nil, nil, "") == nil || called {
		t.Fatal("redirect crossed credential boundary")
	}
}
func TestCommonEnvelopeAndPollingPace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer atk_test" || r.Header.Get("Idempotency-Key") == "" {
			t.Error("missing credentials or idempotency")
		}
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(429)
		w.Write([]byte(`{"ok":false,"error":{"code":"SLOW_DOWN","message":"Polling too frequently"}}`))
	}))
	defer server.Close()
	c, _ := New(server.URL, "atk_test", true)
	err := c.Do(context.Background(), "POST", "/api/device/poll", map[string]string{"request_id": "public-test"}, nil, "")
	var problem *Error
	if !errors.As(err, &problem) || problem.RetryAfter != 15*time.Second || problem.ExitCode() != 7 {
		t.Fatalf("wrong polling behavior: %v", err)
	}
}
