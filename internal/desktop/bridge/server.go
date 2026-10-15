// SPDX-License-Identifier: GPL-3.0-or-later

// Package bridge implements the privileged, short-lived desktop helper. It
// exposes status and per-key up/down/leave only, never credentials or arbitrary CLI.
package bridge

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail-client/internal/desktop"
)

type Backend interface {
	Status(context.Context) (desktop.Snapshot, error)
	Toggle(context.Context, desktop.Action) error
	StartService(context.Context) error
}

type Server struct {
	Session desktop.Session
	Backend Backend
	last    atomic.Int64
	cancel  context.CancelFunc
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(status int, message string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
	}
	if r.Host != "127.0.0.1:"+strconv.Itoa(s.Session.Port) || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || r.URL.RawQuery != "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Session.Secret)) != 1 {
		fail(http.StatusForbidden, "desktop session authorization is required")
		return
	}
	s.last.Store(time.Now().UnixNano())
	if r.Method == "GET" && r.URL.Path == "/v1/status" {
		status, err := s.Backend.Status(r.Context())
		if err != nil {
			fail(503, err.Error())
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		_ = encoder.Encode(status)
		return
	}
	if r.Method != "POST" {
		fail(404, "unknown desktop operation")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fail(415, "JSON is required")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	var err error
	switch r.URL.Path {
	case "/v1/vpn":
		var input desktop.Action
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			fail(400, "invalid VPN action")
			return
		}
		if _, err := uuid.Parse(input.ID); err != nil || input.Action != "up" && input.Action != "down" && input.Action != "leave" {
			fail(403, "only per-VPN connect, disconnect and removal are allowed")
			return
		}
		err = s.Backend.Toggle(r.Context(), input)
	case "/v1/service/start", "/v1/close":
		var input struct{}
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			fail(400, "invalid desktop action")
			return
		}
		if r.URL.Path == "/v1/service/start" {
			err = s.Backend.StartService(r.Context())
		} else if s.cancel != nil {
			s.cancel()
		}
	default:
		fail(404, "unknown desktop operation")
		return
	}
	if err != nil {
		fail(409, err.Error())
		return
	}
	_, _ = io.WriteString(w, "{}\n")
}

// Serve exits when the window closes or stops sending authenticated heartbeats.
// Ending this helper never brings any VPN down or stops the machine agent.
func (s *Server) Serve(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(s.Session.Port))
	if err != nil {
		return err
	}
	s.last.Store(time.Now().UnixNano())
	server := &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 * 1024}
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = server.Shutdown(shutdown)
				cancel()
				return
			case <-tick.C:
				if time.Since(time.Unix(0, s.last.Load())) > 30*time.Second {
					s.cancel()
				}
			}
		}
	}()
	err = server.Serve(listener)
	s.cancel()
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
