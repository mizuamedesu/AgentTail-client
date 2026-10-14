// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUpdateVersionOrdering(t *testing.T) {
	for _, pair := range [][2]string{
		{"0.1.0-dev.9", "0.1.0-dev.10"},
		{"0.1.0-dev.17", "0.1.0"},
		{"0.1.9", "0.1.10"},
		{"0.9.0", "0.10.0"},
		{"9.0.0", "10.0.0"},
		{"1.0.0-alpha", "1.0.0-alpha.1"},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta"},
		{"1.0.0-beta.11", "1.0.0-rc.1"},
		{"1.0.0-dev.99999999999999999999", "1.0.0-dev.100000000000000000000"},
	} {
		for _, order := range []struct {
			left, right string
			want        int
		}{{pair[0], pair[1], -1}, {pair[1], pair[0], 1}, {pair[0], pair[0], 0}} {
			got, ok := compareVersions(order.left, order.right)
			if !ok || got != order.want {
				t.Errorf("compare %q / %q = %d, %v; want %d", order.left, order.right, got, ok, order.want)
			}
		}
	}
	for _, invalid := range []string{"dev", "1.2", "v1.2.3", "01.2.3", "1.2.3-dev.01", "1.2.3\nUpdate now"} {
		if _, ok := compareVersions(invalid, "1.2.3"); ok {
			t.Errorf("invalid or unversioned build accepted: %q", invalid)
		}
	}
}

func TestAvailableUpdateVerifiedCacheAndSequence(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	verifyFixture := func(raw, signature []byte, at time.Time) (Manifest, error) {
		return verify(raw, signature, &key.PublicKey, at)
	}
	fixture := func(version string, sequence uint64, expires time.Time) Manifest {
		raw := []byte(fmt.Sprintf("agenttail-manifest-v1\nversion %s\nsequence %d\ncreated %d\nexpires %d\n", version, sequence, now.Add(-time.Hour).Unix(), expires.Unix()))
		for _, role := range []string{"vpn", "wintun", "license"} {
			raw = append(raw, []byte(fmt.Sprintf("file %s %s %s native-%s 3 %s -\n", runtime.GOOS, runtime.GOARCH, role, role, strings.Repeat("a", 64)))...)
		}
		sum := sha256.Sum256(raw)
		sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if e != nil {
			t.Fatal(e)
		}
		return Manifest{Raw: raw, Signature: sig}
	}
	source := "https://updates.example.invalid/stable"
	newer := fixture("0.1.0-dev.20", 20, now.Add(24*time.Hour))
	expired := fixture("0.1.0-dev.20", 20, now.Add(-time.Minute))
	for _, name := range []string{"fetch", "cached", "equal", "older", "sequence rollback", "different channel", "tampered cache", "tampered response", "expired cache", "outage with cache", "outage without cache", "retry cooldown", "deadline cooldown", "unversioned build"} {
		t.Run(name, func(t *testing.T) {
			cachePath := filepath.Join(t.TempDir(), "update.json")
			cached := updateCache{Source: source, CheckedAt: now.Unix(), Raw: newer.Raw, Signature: newer.Signature}
			current, sequence, want, wantFetch := "0.1.0-dev.17", uint64(17), "0.1.0-dev.20", 0
			response, fetchError := newer, error(nil)
			switch name {
			case "fetch":
				cached = updateCache{}
				wantFetch = 1
			case "equal":
				current, want = "0.1.0-dev.20", ""
			case "older":
				current, want = "0.1.0-dev.21", ""
			case "sequence rollback":
				sequence, want = 20, ""
			case "different channel":
				cached.Source, wantFetch = "https://updates.example.invalid/nanokvm", 1
			case "tampered cache":
				cached.Raw = append(append([]byte{}, newer.Raw...), '\n')
				wantFetch = 1
			case "tampered response":
				cached = updateCache{}
				response.Raw = append(append([]byte{}, newer.Raw...), '\n')
				want, wantFetch = "", 1
			case "expired cache":
				cached.Raw, cached.Signature, wantFetch = expired.Raw, expired.Signature, 1
			case "outage with cache":
				cached.CheckedAt = now.Add(-2 * time.Hour).Unix()
				fetchError, wantFetch = errors.New("offline"), 1
			case "outage without cache":
				cached = updateCache{}
				fetchError, want, wantFetch = errors.New("offline"), "", 1
			case "retry cooldown":
				cached.Failed, cached.Raw, cached.Signature, want = true, nil, nil, ""
			case "deadline cooldown":
				cached = updateCache{}
				fetchError, want, wantFetch = context.DeadlineExceeded, "", 1
			case "unversioned build":
				current, want = "dev", ""
			}
			data, _ := json.Marshal(cached)
			if err := os.WriteFile(cachePath, data, 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			fetch := func(_ context.Context, origin string) (Manifest, error) {
				calls++
				if origin != source {
					t.Fatal("wrong release channel requested")
				}
				return response, fetchError
			}
			got, _ := availableUpdate(context.Background(), source, current, sequence, cachePath, now, fetch, verifyFixture)
			if got != want || calls != wantFetch {
				t.Fatalf("tip=%q fetches=%d; want %q / %d", got, calls, want, wantFetch)
			}
			if calls > 0 {
				// The next command uses the verified cache or failure cooldown.
				calls = 0
				again, _ := availableUpdate(context.Background(), source, current, sequence, cachePath, now.Add(time.Second), fetch, verifyFixture)
				if again != want || calls != 0 {
					t.Fatalf("second command did not reuse metadata/cooldown: %q, %d", again, calls)
				}
			}
		})
	}
	// The production trust key must reject an otherwise correctly signed fixture.
	if _, err := Verify(newer.Raw, newer.Signature, now); err == nil {
		t.Fatal("update notification trusted a test signing key")
	}
}

func TestUpdateMetadataRequests(t *testing.T) {
	for _, mode := range []string{"metadata only", "redirect", "oversized manifest", "oversized signature", "HTTP rejected", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			var paths []string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("metadata request sent account credentials")
				}
				if mode == "redirect" {
					http.Redirect(w, r, "/must-not-follow", http.StatusFound)
				} else if mode == "oversized manifest" {
					fmt.Fprint(w, strings.Repeat("a", MaxManifest+1))
				} else if mode == "oversized signature" && strings.HasSuffix(r.URL.Path, ".sig") {
					fmt.Fprint(w, strings.Repeat("a", 2049))
				} else {
					fmt.Fprint(w, "public metadata")
				}
			}))
			defer server.Close()
			client, transport := releaseClient()
			defer transport.CloseIdleConnections()
			transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			source := server.URL + "/stable"
			if mode == "HTTP rejected" {
				source = strings.Replace(source, "https:", "http:", 1)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			_, _, err := releaseMetadata(ctx, client, source)
			if mode == "metadata only" {
				if err != nil || strings.Join(paths, ",") != "/stable/manifest.txt,/stable/manifest.sig" {
					t.Fatalf("requested executable files or lost metadata: %v / %v", paths, err)
				}
			} else if err == nil {
				t.Fatal("unsafe or canceled metadata request succeeded")
			}
			for _, path := range paths {
				if path == "/must-not-follow" {
					t.Fatal("release redirect was followed")
				}
			}
		})
	}
}
