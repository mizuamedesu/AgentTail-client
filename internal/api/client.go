// Package api is the common HTTPS contract used by every native client.
// It never accepts a plaintext account password or logs credentials/bodies.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Client struct {
	Origin string
	Token  string
	HTTP   *http.Client
}

type Error struct {
	Code       string        `json:"code"`
	Message    string        `json:"message"`
	RequestID  string        `json:"request_id,omitempty"`
	Status     int           `json:"-"`
	RetryAfter time.Duration `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func (e *Error) ExitCode() int {
	switch e.Code {
	case "INVALID_REQUEST":
		return 2
	case "UNAUTHENTICATED", "EXPIRED_TOKEN":
		return 3
	case "FORBIDDEN", "ACCESS_DENIED", "KILLED":
		return 4
	case "NOT_FOUND":
		return 5
	case "CONFLICT", "ALREADY_CONSUMED", "AGENT_OFFLINE":
		return 6
	case "QUOTA_EXCEEDED", "RATE_LIMITED", "SLOW_DOWN":
		return 7
	case "UNAVAILABLE", "NETWORK":
		return 8
	default:
		return 9
	}
}

func New(origin, token string, allowLocalHTTP bool) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, &Error{Code: "INVALID_REQUEST", Message: "server must be an HTTPS origin without a path or credentials"}
	}
	local := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && local && allowLocalHTTP) {
		return nil, &Error{Code: "INVALID_REQUEST", Message: "HTTPS is required (local HTTP needs --allow-local-http)"}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Client{Origin: strings.TrimRight(origin, "/"), Token: token, HTTP: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Do(ctx context.Context, method, path string, input, output any, idempotency string) error {
	if !strings.HasPrefix(path, "/api/") || strings.ContainsAny(path, "\r\n") {
		return errors.New("invalid API path")
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return errors.New("invalid API input")
		}
		defer clear(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.Origin+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid API request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "AgentTail/v1")
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if method != http.MethodGet {
		if idempotency == "" {
			idempotency = uuid.NewString()
		}
		request.Header.Set("Idempotency-Key", idempotency)
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return &Error{Code: "NETWORK", Message: "control server could not be reached"}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return &Error{Code: "NETWORK", Message: "control response is invalid or too large"}
	}
	defer clear(data)
	var envelope struct {
		OK      *bool           `json:"ok"`
		Data    json.RawMessage `json:"data"`
		Error   *Error          `json:"error"`
		Code    string          `json:"code"`
		Message string          `json:"message"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return &Error{Code: "NETWORK", Message: "control server returned an invalid response", Status: response.StatusCode}
	}
	if response.StatusCode >= 300 || envelope.OK != nil && !*envelope.OK {
		problem := envelope.Error
		if problem == nil {
			code := "INTERNAL"
			switch response.StatusCode {
			case 400, 422:
				code = "INVALID_REQUEST"
			case 401:
				code = "UNAUTHENTICATED"
			case 403:
				code = "FORBIDDEN"
			case 404:
				code = "NOT_FOUND"
			case 409:
				code = "CONFLICT"
			case 429:
				code = "RATE_LIMITED"
			case 502, 503, 504:
				code = "UNAVAILABLE"
			}
			problem = &Error{Code: code, Message: envelope.Message}
			if problem.Message == "" {
				problem.Message = "control request was rejected"
			}
		}
		problem.Status = response.StatusCode
		if seconds, parseErr := strconv.Atoi(response.Header.Get("Retry-After")); parseErr == nil && seconds >= 1 && seconds <= 300 {
			problem.RetryAfter = time.Duration(seconds) * time.Second
		}
		return problem
	}
	if output == nil {
		return nil
	}
	if envelope.OK != nil {
		data = envelope.Data
	}
	if err = json.Unmarshal(data, output); err != nil {
		return &Error{Code: "NETWORK", Message: "control response does not match the API contract"}
	}
	return nil
}

func (c *Client) Pages(ctx context.Context, path string, output any) error {
	var all []json.RawMessage
	after := ""
	seen := map[string]bool{}
	for {
		var page struct {
			Items []json.RawMessage `json:"items"`
			Next  *string           `json:"next"`
		}
		endpoint := path
		if after != "" {
			endpoint += "?after=" + url.QueryEscape(after)
		}
		if err := c.Do(ctx, "GET", endpoint, nil, &page, ""); err != nil {
			return err
		}
		all = append(all, page.Items...)
		if len(all) > 200000 {
			return fmt.Errorf("result set is too large; use the paginated API")
		}
		if page.Next == nil || *page.Next == "" {
			break
		}
		if seen[*page.Next] {
			return errors.New("invalid pagination cursor")
		}
		seen[*page.Next] = true
		after = *page.Next
	}
	data, err := json.Marshal(all)
	if err != nil {
		return err
	}
	defer clear(data)
	return json.Unmarshal(data, output)
}
