// SPDX-License-Identifier: GPL-3.0-or-later

package localstate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/mizuamedesu/AgentTail-client/internal/secrets"
)

const Version = 1

type Key struct {
	VPNID   string `json:"vpn_id,omitempty"`
	ID      string `json:"key_id"`
	Name    string `json:"name"`
	Public  string `json:"public_key"`
	GrantID string `json:"grant_id"`
	Expires int64  `json:"expires_at"`
	AutoUp  bool   `json:"auto_up"`
}
type Config struct {
	Version        int    `json:"version"`
	Server         string `json:"server"`
	WebOrigin      string `json:"web_origin,omitempty"`
	AllowLocalHTTP bool   `json:"allow_local_http,omitempty"`
	Keys           []Key  `json:"keys"`
}
type KeyCredential struct {
	KeyID   string `json:"key_id"`
	OwnerID string `json:"owner_id,omitempty"`
	Public  string `json:"public_key"`
	Private []byte `json:"private_key"`
	Token   string `json:"credential"`
	Expires int64  `json:"expires_at"`
}
type Session struct {
	Token   string `json:"token"`
	OwnerID string `json:"owner_id"`
	Email   string `json:"email"`
	Role    string `json:"role"`
	Server  string `json:"server"`
}
type State struct{ Store *secrets.Store }

func New(directory string) (*State, error) {
	store, err := secrets.New(directory)
	if err != nil {
		return nil, err
	}
	return &State{Store: store}, nil
}
func (s *State) Read() (Config, error) {
	data, err := os.ReadFile(filepath.Join(s.Store.Dir, "config.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Config{Version: Version, Keys: []Key{}}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err = json.Unmarshal(data, &c); err != nil {
		return Config{}, errors.New("invalid local configuration")
	}
	if c.Version != Version {
		return Config{}, errors.New("unsupported local configuration version")
	}
	return c, nil
}

// Update serializes all CLI/agent edits and atomically replaces metadata. No
// plaintext key, password, derived authentication value or vault key belongs here.
func (s *State) Update(change func(*Config) error) error {
	lock, err := os.OpenFile(filepath.Join(s.Store.Dir, "config.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = lockFile(lock); err != nil {
		return err
	}
	defer unlockFile(lock)
	c, err := s.Read()
	if err != nil {
		return err
	}
	if err = change(&c); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Store.Dir, ".config-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), filepath.Join(s.Store.Dir, "config.json"))
}
func (c Config) Find(name string) (Key, error) {
	for _, k := range c.Keys {
		if k.Name == name || k.ID == name || k.VPNID != "" && k.VPNID == name {
			return k, nil
		}
	}
	return Key{}, errors.New("no locally authorized key matches that name")
}
func (s *State) LoadKey(key Key) (KeyCredential, error) {
	var credential KeyCredential
	if err := s.Store.Get("key/"+key.ID, &credential); err != nil {
		return credential, err
	}
	if credential.KeyID != key.ID || credential.Public != key.Public || !strings.HasPrefix(credential.Token, "atk_") || len(credential.Private) != 32 {
		clear(credential.Private)
		return KeyCredential{}, errors.New("stored key credential does not match its scope")
	}
	return credential, nil
}
func (s *State) LoadSession(administrator bool) (Session, error) {
	scope := "account"
	if administrator {
		scope = "admin"
	}
	var session Session
	if err := s.Store.Get("session/"+scope, &session); err != nil {
		return Session{}, err
	}
	if session.Token == "" || strings.HasPrefix(session.Token, "atk_") || administrator && session.Role != "admin" {
		return Session{}, errors.New("stored account session has an invalid scope")
	}
	return session, nil
}
