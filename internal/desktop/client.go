// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type Client struct {
	session Session
	http    *http.Client
}

func NewClient(s Session) *Client {
	return &Client{session: s, http: &http.Client{Timeout: 15 * time.Second,
		Transport:     &http.Transport{Proxy: nil, MaxIdleConns: 2},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) request(ctx context.Context, method, path string, body any, result any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:"+strconv.Itoa(c.session.Port)+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+c.session.Secret)
	r.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return errors.New("the desktop helper is not reachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure) == nil && failure.Error != "" {
			return errors.New(failure.Error)
		}
		return fmt.Errorf("desktop helper rejected the request (%d)", response.StatusCode)
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 512*1024)).Decode(result)
	}
	return nil
}

func (c *Client) Status(ctx context.Context) (Snapshot, error) {
	var s Snapshot
	err := c.request(ctx, "GET", "/v1/status", nil, &s)
	if err == nil && s.Version != c.session.Version {
		err = errors.New("desktop and helper versions differ; reopen AgentTail")
	}
	return s, err
}

func (c *Client) Toggle(ctx context.Context, id, action string) error {
	return c.request(ctx, "POST", "/v1/vpn", Action{ID: id, Action: action}, nil)
}

func (c *Client) StartService(ctx context.Context) error {
	return c.request(ctx, "POST", "/v1/service/start", struct{}{}, nil)
}

func (c *Client) Close(ctx context.Context) { _ = c.request(ctx, "POST", "/v1/close", struct{}{}, nil) }
