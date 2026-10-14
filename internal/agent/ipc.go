// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/api"
)

func LocalRequest(ctx context.Context, directory, keyID, action string, output any) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialIPC(ctx, directory) }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	method, path := http.MethodGet, "/v1/status"
	var body []byte
	if action == "status" {
		if keyID != "" {
			path += "?key_id=" + url.QueryEscape(keyID)
		}
	} else {
		method, path = http.MethodPost, "/v1/key"
		body, _ = json.Marshal(map[string]string{"key_id": keyID, "action": action})
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://agenttail.local"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AgentTail-Key-ID", keyID)
	response, err := client.Do(request)
	if err != nil {
		return &api.Error{Code: "AGENT_OFFLINE", Message: "local agent is not reachable; start the installed service or run agenttail agent run"}
	}
	defer response.Body.Close()
	var envelope struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error *api.Error      `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 512*1024)).Decode(&envelope) != nil {
		return &api.Error{Code: "INTERNAL", Message: "invalid local agent response"}
	}
	if !envelope.OK || response.StatusCode >= 300 {
		if envelope.Error != nil {
			return envelope.Error
		}
		return &api.Error{Code: "INTERNAL", Message: "local request failed"}
	}
	if output == nil {
		return nil
	}
	return json.Unmarshal(envelope.Data, output)
}
