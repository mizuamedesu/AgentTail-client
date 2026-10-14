package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail/internal/api"
	"github.com/mizuamedesu/AgentTail/internal/localstate"
)

type managed struct {
	key    *Key
	cancel context.CancelFunc
	done   chan struct{}
	grant  string
}
type Manager struct {
	state *localstate.State
	mu    sync.Mutex
	keys  map[string]*managed
	ctx   context.Context
}

func Serve(ctx context.Context, state *localstate.State) error {
	unlock, err := state.AgentLock()
	if err != nil {
		return err
	}
	defer unlock()
	listener, err := listenIPC(state.Store.Dir)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m := &Manager{state: state, keys: map[string]*managed{}, ctx: ctx}
	defer m.close()
	if err = m.reload(); err != nil {
		return err
	}
	server := &http.Server{Handler: http.HandlerFunc(m.handle), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	defer server.Close()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err = <-result:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-tick.C:
			if err = m.reload(); err != nil {
				return err
			}
		}
	}
}
func (m *Manager) reload() error {
	config, err := m.state.Read()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := map[string]localstate.Key{}
	for _, key := range config.Keys {
		wanted[key.ID] = key
	}
	for id, old := range m.keys {
		key, exists := wanted[id]
		if !exists || key.GrantID != old.grant || old.key.options.Client.Origin != config.Server {
			old.key.gate.Stop()
			old.cancel()
			<-old.done
			delete(m.keys, id)
		}
	}
	for _, key := range config.Keys {
		if m.keys[key.ID] != nil {
			continue
		}
		credential, err := m.state.LoadKey(key)
		if err != nil {
			return err
		}
		client, err := api.New(config.Server, credential.Token, config.AllowLocalHTTP)
		if err != nil {
			clear(credential.Private)
			return err
		}
		worker, err := NewKey(Options{Client: client, Metadata: key, Credential: credential, State: m.state})
		clear(credential.Private)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(m.ctx)
		entry := &managed{key: worker, cancel: cancel, done: make(chan struct{}), grant: key.GrantID}
		m.keys[key.ID] = entry
		go func() { defer close(entry.done); worker.Run(ctx) }()
	}
	return nil
}
func (m *Manager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range m.keys {
		entry.key.gate.Stop()
		entry.cancel()
	}
	for _, entry := range m.keys {
		<-entry.done
	}
}

// The OS ACL restricts this socket to machine administrators. Every request
// must select a locally installed, key-scoped credential; no account session,
// private-key export, arbitrary command, or arbitrary API proxy is exposed.
func (m *Manager) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code, message string, status int) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": api.Error{Code: code, Message: message}})
	}
	if r.Host != "agenttail.local" || r.Header.Get("Origin") != "" {
		fail("FORBIDDEN", "local agent clients only", 403)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/v1/status" {
		id := r.URL.Query().Get("key_id")
		m.mu.Lock()
		items := []Status{}
		for key, entry := range m.keys {
			if id == "" || id == key {
				items = append(items, entry.key.Status())
			}
		}
		m.mu.Unlock()
		if id != "" && len(items) == 0 {
			fail("FORBIDDEN", "key is not authorized on this machine", 403)
			return
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{"agent": "running", "keys": items}})
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/key" {
		fail("NOT_FOUND", "unknown local operation", 404)
		return
	}
	var input struct {
		KeyID  string `json:"key_id"`
		Action string `json:"action"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		fail("INVALID_REQUEST", "invalid local request", 400)
		return
	}
	if _, err := uuid.Parse(input.KeyID); err != nil {
		fail("INVALID_REQUEST", "key_id is required", 400)
		return
	}
	if r.Header.Get("X-AgentTail-Key-ID") != input.KeyID {
		fail("FORBIDDEN", "local request key scope mismatch", 403)
		return
	}
	m.mu.Lock()
	entry := m.keys[input.KeyID]
	m.mu.Unlock()
	if entry == nil {
		// A just-approved device can request up before the periodic reload.
		// Load only credentials already persisted in this machine's OS store.
		if err := m.reload(); err != nil {
			fail("INTERNAL", "local credentials could not be loaded", 500)
			return
		}
		m.mu.Lock()
		entry = m.keys[input.KeyID]
		m.mu.Unlock()
	}
	if entry == nil {
		fail("FORBIDDEN", "key is not authorized on this machine", 403)
		return
	}
	var err error
	switch input.Action {
	case "up":
		err = entry.key.SetDesired(true)
	case "down":
		err = entry.key.SetDesired(false)
	case "sync":
		entry.key.RequestSync()
	default:
		fail("FORBIDDEN", "operation is outside the local key scope", 403)
		return
	}
	if err != nil {
		var p *api.Error
		if errors.As(err, &p) {
			fail(p.Code, p.Message, 403)
		} else {
			fail("INTERNAL", "local configuration could not be saved", 500)
		}
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": entry.key.Status()})
}
