// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChecksumManifestAndLegacyPolicy(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	raw := []byte(fmt.Sprintf("agenttail-manifest-v1\nversion 1.2.3\nsequence 7\ncreated %d\nexpires %d\nfile linux amd64 vpn agenttail-linux-amd64 3 %s -\n", now.Unix(), now.Add(time.Hour).Unix(), strings.Repeat("a", 64)))
	checksum := []byte(fmt.Sprintf("%x  manifest.txt\n", sha256.Sum256(raw)))
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, "manifest.txt"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifest.sha256"), checksum, 0600); err != nil {
		t.Fatal(err)
	}
	m, root, err := readBundleWithVerification(bundle, ChecksumVerification)
	if err != nil || m.Version != "1.2.3" {
		t.Fatal("checksum bundle rejected", err)
	}
	root.Close()
	if _, root, err = readBundle(bundle); err == nil {
		root.Close()
		t.Fatal("legacy signature policy accepted a hash-only bundle")
	}
	if (&Record{}).VerificationMethod() != SignatureVerification {
		t.Fatal("legacy installation lost signature policy")
	}
	for _, proof := range [][]byte{nil, []byte(strings.Repeat("0", 64) + "  manifest.txt\n"), []byte(fmt.Sprintf("%x  other.txt\n", sha256.Sum256(raw))), append(append([]byte{}, checksum...), '\n')} {
		if _, err := VerifyChecksum(raw, proof, now); err == nil {
			t.Fatal("invalid checksum accepted")
		}
	}
	if _, err := VerifyChecksum(append(append([]byte{}, raw...), '\n'), checksum, now); err == nil {
		t.Fatal("changed manifest accepted")
	}
	if _, err := VerifyChecksum(raw, checksum, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired checksum release accepted")
	}
	if _, err := verifyRelease(raw, checksum, "unknown", now); err == nil {
		t.Fatal("unknown verification method accepted")
	}
}

func TestChecksumMetadataDoesNotFetchSignaturesOrFollowRedirects(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		var paths []string
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("sent account credentials")
			}
			if redirect {
				http.Redirect(w, r, "/other", http.StatusFound)
			} else {
				fmt.Fprint(w, "public release metadata")
			}
		}))
		client, transport := releaseClient()
		transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		_, _, err := releaseMetadataWithVerification(context.Background(), client, server.URL, ChecksumVerification)
		server.Close()
		transport.CloseIdleConnections()
		if redirect && err == nil {
			t.Fatal("followed a release redirect")
		}
		if !redirect && (err != nil || strings.Join(paths, ",") != "/manifest.txt,/manifest.sha256") {
			t.Fatal("wrong checksum metadata requests", paths, err)
		}
	}
}
