// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
)

func TestResolveOrigins(t *testing.T) {
	for _, test := range []struct {
		name, server, web   string
		config              localstate.Config
		local               bool
		wantServer, wantWeb string
	}{
		{name: "official defaults", wantServer: defaultServer, wantWeb: defaultWebOrigin},
		{name: "existing official installation", config: localstate.Config{Server: defaultServer}, wantServer: defaultServer, wantWeb: defaultWebOrigin},
		{name: "legacy Worker", server: "https://agenttail.fasutotesuto.workers.dev", wantServer: "https://agenttail.fasutotesuto.workers.dev", wantWeb: defaultWebOrigin},
		{name: "custom shared host", server: "https://vpn.example.test", wantServer: "https://vpn.example.test", wantWeb: "https://vpn.example.test"},
		{name: "explicit split hosts", server: "https://api.example.test/", web: "https://web.example.test/", wantServer: "https://api.example.test", wantWeb: "https://web.example.test"},
		{name: "saved split hosts", config: localstate.Config{Server: "https://api.example.test", WebOrigin: "https://web.example.test"}, wantServer: "https://api.example.test", wantWeb: "https://web.example.test"},
		{name: "explicit Web override", web: "https://new.example.test", config: localstate.Config{Server: "https://api.example.test", WebOrigin: "https://old.example.test"}, wantServer: "https://api.example.test", wantWeb: "https://new.example.test"},
		{name: "API override drops saved Web", server: "https://other.example.test", config: localstate.Config{Server: defaultServer, WebOrigin: defaultWebOrigin}, wantServer: "https://other.example.test", wantWeb: "https://other.example.test"},
		{name: "local split hosts", server: "http://localhost:8787", web: "http://localhost:8788", local: true, wantServer: "http://localhost:8787", wantWeb: "http://localhost:8788"},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := options{server: test.server, webOrigin: test.web, config: test.config, local: test.local}
			if err := o.resolveOrigins(); err != nil {
				t.Fatal(err)
			}
			if o.server != test.wantServer || o.webOrigin != test.wantWeb {
				t.Fatalf("got %s / %s, want %s / %s", o.server, o.webOrigin, test.wantServer, test.wantWeb)
			}
			var saved localstate.Config
			if err := o.saveOrigin(&saved); err != nil {
				t.Fatal(err)
			}
			reloaded := options{config: saved}
			if err := reloaded.resolveOrigins(); err != nil || reloaded.server != o.server || reloaded.webOrigin != o.webOrigin {
				t.Fatal("origin configuration did not survive reload", err)
			}
		})
	}
	for _, web := range []string{"http://web.example.test", "http://localhost:8788", "https://user:pass@web.example.test", "https://web.example.test/path", "https://web.example.test?redirect=1", "https://web.example.test#fragment", "javascript:alert(1)"} {
		o := options{webOrigin: web}
		if err := o.resolveOrigins(); err == nil {
			t.Errorf("accepted unsafe Web origin %q", web)
		}
	}
}

func TestDeviceApprovalURL(t *testing.T) {
	o := options{}
	if err := o.resolveOrigins(); err != nil {
		t.Fatal(err)
	}
	key, err := cryptobox.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := cryptobox.RecipientFingerprint(key.Public, "request-test")
	if err != nil {
		t.Fatal(err)
	}
	link, err := o.deviceApprovalURL(defaultWebOrigin+"/device", "ABCD-EFGH", fingerprint)
	if err != nil {
		t.Fatal("official split-origin approval failed", link, err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	// Browsers expose the escaped fragment through location.hash; decode once.
	fragment, err := url.ParseQuery(u.EscapedFragment())
	if err != nil || fragment.Get("recipient") != fingerprint || u.RequestURI() != "/device?code=ABCD-EFGH" {
		t.Fatal("CLI fingerprint must be preserved in the fragment, never the HTTP URL", err)
	}
	for _, missing := range []string{"", "SHA256:invalid"} {
		if _, err := o.deviceApprovalURL(defaultWebOrigin+"/device", "ABCD-EFGH", missing); err == nil {
			t.Fatal("approval link omitted the local trust value")
		}
	}
	for _, code := range []string{"", "abcd-efgh", "ABCD-EFGH\n", "ABCD-EFGH\rFORGED", "ABCD-EFGH\x1b[2J", "ABCD-EFGH\u202e", "ABCD-EFGH#recipient=forged"} {
		if link, err := o.deviceApprovalURL(defaultWebOrigin+"/device", code, fingerprint); err == nil || link != "" {
			t.Fatal("untrusted device code could alter terminal approval output")
		}
	}
	for _, link := range []string{
		defaultServer + "/device", "https://other.mizuame.app/device", defaultWebOrigin + ".attacker.test/device",
		"https://user@agenttail.mizuame.app/device", "http://agenttail.mizuame.app/device",
		defaultWebOrigin + "/reset", defaultWebOrigin + "/%64evice", defaultWebOrigin + "/device#fragment",
		defaultWebOrigin + "/device?redirect=https://attacker.test", "//agenttail.mizuame.app/device",
	} {
		if _, err := o.deviceApprovalURL(link, "ABCD-EFGH", fingerprint); err == nil {
			t.Errorf("accepted untrusted approval URL %q", link)
		}
	}
}

func TestResetTokenAcrossAPIAndWebOrigins(t *testing.T) {
	o := options{}
	if err := o.resolveOrigins(); err != nil {
		t.Fatal(err)
	}
	const token = "public-test-reset-token_1234567890"
	for _, link := range []string{
		token, "  " + token + "\n",
		defaultServer + "/api/auth/reset-password/" + token + "?callbackURL=" + url.QueryEscape(defaultWebOrigin+"/reset"),
		defaultWebOrigin + "/reset?token=" + token,
	} {
		value, err := o.resetToken(link)
		if err != nil || value != token {
			t.Errorf("valid reset link failed: %v", err)
		}
	}
	for _, link := range []string{
		"short", strings.Repeat("x", 129), "https://attacker.test/reset?token=" + token,
		"https://other.mizuame.app/reset?token=" + token, defaultWebOrigin + ".attacker.test/reset?token=" + token,
		"https://user@agenttail.mizuame.app/reset?token=" + token, "http://agenttail.mizuame.app/reset?token=" + token,
		defaultWebOrigin + "/other?token=" + token, defaultServer + "/reset?token=" + token,
		defaultWebOrigin + "/api/auth/reset-password/" + token, defaultWebOrigin + "/reset#token=" + token,
		defaultWebOrigin + "/reset?token=" + token + "&token=" + token, defaultWebOrigin + "/reset?token=%zz",
		defaultServer + "/api/auth/reset-password/" + token + "/extra", defaultServer + "/api/auth/reset-password/",
	} {
		if _, err := o.resetToken(link); err == nil {
			t.Errorf("accepted untrusted or invalid reset link %q", link)
		}
	}
}

func TestResetRequestUsesAPIWithWebCallback(t *testing.T) {
	var received bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		if r.Method != "POST" || r.URL.Path != "/api/auth/request-password-reset" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected reset request destination or credentials")
		}
		var input map[string]string
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		if input["email"] != "fixture@example.test" || input["redirectTo"] != "https://web.example.test/reset" {
			t.Error("reset request did not use the configured Web callback")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":true}`))
	}))
	defer server.Close()
	o := options{ctx: context.Background(), server: server.URL, webOrigin: "https://web.example.test", local: true}
	if err := o.resolveOrigins(); err != nil {
		t.Fatal(err)
	}
	if err := o.requestPasswordReset("fixture@example.test"); err != nil {
		t.Fatal(err)
	}
	if !received {
		t.Fatal("reset request was not sent to the API")
	}
}

func TestLegacyOfficialServerAcceptsCanonicalResetEmail(t *testing.T) {
	const token = "public-test-reset-token_1234567890"
	for _, server := range []string{legacyServer, defaultWebOrigin} {
		o := options{config: localstate.Config{Server: server}}
		if err := o.resolveOrigins(); err != nil {
			t.Fatal(err)
		}
		value, err := o.resetToken(defaultServer + "/api/auth/reset-password/" + token)
		if err != nil || value != token {
			t.Fatal("legacy installation rejected its canonical API email link", err)
		}
	}
	o := options{server: "https://custom.example.test", webOrigin: defaultWebOrigin}
	if _, err := o.resetToken(defaultServer + "/api/auth/reset-password/" + token); err == nil {
		t.Fatal("custom API accepted another deployment's reset token")
	}
}
