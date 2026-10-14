package cli

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/mizuamedesu/AgentTail/internal/api"
	"github.com/mizuamedesu/AgentTail/internal/cryptobox"
)

const defaultWebOrigin = "https://agenttail.mizuame.app"

var deviceUserCode = regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`)

const legacyServer = "https://agenttail.fasutotesuto.workers.dev"

func (o *options) resolveOrigins() error {
	if o.server == "" {
		o.server = o.config.Server
	}
	if o.server == "" {
		o.server = defaultServer
	}
	o.server = strings.TrimRight(o.server, "/")
	o.local = o.local || o.config.AllowLocalHTTP
	if _, err := api.New(o.server, "", o.local); err != nil {
		return err
	}
	// A saved Web origin belongs to its saved API, never to a --server override.
	if o.webOrigin == "" && o.server == strings.TrimRight(o.config.Server, "/") {
		o.webOrigin = o.config.WebOrigin
	}
	if o.webOrigin == "" {
		switch o.server {
		case defaultServer, legacyServer:
			o.webOrigin = defaultWebOrigin
		default:
			o.webOrigin = o.server
		}
	}
	o.webOrigin = strings.TrimRight(o.webOrigin, "/")
	if _, err := api.New(o.webOrigin, "", o.local); err != nil {
		return errors.New("Web origin must be an HTTPS origin without a path or credentials (loopback HTTP needs --allow-local-http)")
	}
	return nil
}

// Account links are displayed or parsed locally. They never change the API
// destination or receive the account/device bearer credential.
func parseAccountLink(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawPath != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("invalid account link")
	}
	return u, nil
}

func (o *options) deviceApprovalURL(raw, code, recipientFingerprint string) (string, error) {
	return o.approvalURL(raw, code, recipientFingerprint, "/device")
}
func (o *options) approvalURL(raw, code, recipientFingerprint, path string) (string, error) {
	// Server-controlled terminal escapes must not obscure or replace the
	// locally generated approval link and fingerprint in human-readable output.
	if !deviceUserCode.MatchString(code) {
		return "", errors.New("invalid device user code")
	}
	u, err := parseAccountLink(raw)
	if err != nil || u.Scheme+"://"+u.Host != o.webOrigin || u.Path != path || u.RawQuery != "" {
		return "", errors.New("device approval URL does not match the configured Web origin")
	}
	if !strings.HasPrefix(recipientFingerprint, "SHA256:") {
		return "", errors.New("missing recipient fingerprint")
	}
	if _, err := cryptobox.Decode(strings.TrimPrefix(recipientFingerprint, "SHA256:"), 32); err != nil {
		return "", errors.New("invalid recipient fingerprint")
	}
	u.RawQuery = url.Values{"code": {code}}.Encode()
	// A fragment carries the CLI's local trust value to the Web client without
	// asking the API to supply it or including it in HTTP requests/referrers.
	u.Fragment = "recipient=" + recipientFingerprint
	return u.String(), nil
}

var resetTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)

func (o *options) resetToken(input string) (string, error) {
	input = strings.TrimSpace(input)
	if resetTokenPattern.MatchString(input) {
		return input, nil
	}
	u, err := parseAccountLink(input)
	if err != nil {
		return "", errors.New("invalid reset token or link")
	}
	origin := u.Scheme + "://" + u.Host
	var token string
	switch {
	case (origin == o.server || origin == defaultServer && (o.server == legacyServer || o.server == defaultWebOrigin)) && strings.HasPrefix(u.Path, "/api/auth/reset-password/"):
		token = strings.TrimPrefix(u.Path, "/api/auth/reset-password/")
	case origin == o.webOrigin && u.Path == "/reset":
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil || len(query["token"]) != 1 {
			return "", errors.New("invalid reset token or link")
		}
		token = query.Get("token")
	default:
		return "", errors.New("reset link does not match the configured API or Web origin")
	}
	if !resetTokenPattern.MatchString(token) {
		return "", errors.New("invalid reset token or link")
	}
	return token, nil
}
