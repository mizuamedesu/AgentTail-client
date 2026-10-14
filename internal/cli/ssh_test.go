// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"golang.org/x/crypto/ssh"
)

func TestReceiveSSHPrivate(t *testing.T) {
	for _, test := range []struct {
		name, expectedError string
		pin, wrongPublic    bool
	}{
		{name: "name only"},
		{name: "optional public key", pin: true},
		{name: "reject mismatched seed", wrongPublic: true, expectedError: "does not match the selected public key"},
		{name: "reject changed optional pin", pin: true, wrongPublic: true, expectedError: "SSH public key changed during approval"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			pub, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)
			seed := private.Seed()
			defer clear(seed)
			key, err := ssh.NewPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			public := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			approvedPublic, expected := public, ""
			if test.pin {
				expected = public
			}
			if test.wrongPublic {
				other, secret, err := ed25519.GenerateKey(rand.Reader)
				clear(secret)
				if err != nil {
					t.Fatal(err)
				}
				otherKey, err := ssh.NewPublicKey(other)
				if err != nil {
					t.Fatal(err)
				}
				approvedPublic = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherKey)))
			}
			requestID, keyID := uuid.NewString(), uuid.NewString()
			var transfer cryptobox.Transfer
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("Authorization") != "" {
					t.Error("SSH transfer must not require an account or VPN credential")
				}
				var input map[string]string
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					t.Error(err)
					http.Error(w, "invalid input", 400)
					return
				}
				reply := func(data any) { json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": data}) }
				switch r.URL.Path {
				case "/api/ssh-device/start":
					if input["key"] != "work laptop" {
						t.Error("requested SSH key name was not preserved")
					}
					pin, present := input["expected_public_key"]
					if present != test.pin || pin != expected {
						t.Error("expected public key must be optional")
					}
					fingerprint, err := cryptobox.RecipientFingerprint(input["ephemeral_public_key"], requestID)
					if err == nil {
						transfer, err = cryptobox.SealTransfer(input["ephemeral_public_key"], requestID, "ssh/"+keyID, seed, fingerprint)
					}
					if err != nil {
						t.Error(err)
						http.Error(w, "transfer failed", 500)
						return
					}
					reply(map[string]any{"request_id": requestID, "device_secret": "test-device-secret", "user_code": "ABCD-EFGH", "verification_uri": server.URL + "/ssh-device", "interval": 5, "expires_in": 300})
				case "/api/ssh-device/poll":
					if input["request_id"] != requestID || input["device_secret"] != "test-device-secret" {
						t.Error("poll must use the original request and its secret")
					}
					reply(map[string]any{"key_id": keyID, "public_key": approvedPublic, "encrypted_transfer": transfer})
				default:
					t.Error("unexpected SSH transfer request")
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			o := options{ctx: ctx, server: server.URL, webOrigin: server.URL, local: true}
			err = o.receiveSSHPrivate(home, "work laptop", expected)
			path := filepath.Join(home, ".ssh", "agenttail_"+keyID)
			if test.expectedError != "" {
				if err == nil || !strings.Contains(err.Error(), test.expectedError) {
					t.Fatalf("expected %q, got %v", test.expectedError, err)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("mismatched key must not be installed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(raw)
			signer, err := ssh.ParsePrivateKey(raw)
			if err != nil {
				t.Fatal("installed key is not a valid OpenSSH identity")
			}
			if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != public {
				t.Fatal("installed identity differs from the approved SSH key")
			}
		})
	}
}
