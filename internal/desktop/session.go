// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Session is an ephemeral capability for a single desktop window. Only its
// owner, administrators and the elevated helper can read the private file.
type Session struct {
	Port    int    `json:"port"`
	Secret  string `json:"secret"`
	Created int64  `json:"created"`
	Version string `json:"version"`
}

func NewSession(port int, version string) (Session, string, func(), error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Session{}, "", nil, err
	}
	s := Session{Port: port, Secret: base64.RawURLEncoding.EncodeToString(secret), Created: time.Now().Unix(), Version: version}
	dir, err := os.MkdirTemp("", "agenttail-desktop-")
	if err != nil {
		return Session{}, "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err = protectSessionDirectory(dir); err != nil {
		cleanup()
		return Session{}, "", nil, err
	}
	path := filepath.Join(dir, "session.json")
	data, err := json.Marshal(s)
	if err == nil {
		err = os.WriteFile(path, data, 0600)
	}
	if err != nil {
		cleanup()
		return Session{}, "", nil, err
	}
	return s, path, cleanup, nil
}

func ReadSession(path, version string) (Session, error) {
	var s Session
	info, err := os.Lstat(path)
	if err != nil {
		return s, err
	}
	if !filepath.IsAbs(path) || !info.Mode().IsRegular() || info.Size() > 4096 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return s, errors.New("desktop session file must be a private regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return s, errors.New("desktop session file changed")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 4097))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s) != nil || decoder.Decode(new(any)) != io.EOF {
		return s, errors.New("invalid desktop session")
	}
	secret, err := base64.RawURLEncoding.DecodeString(s.Secret)
	if err != nil || len(secret) != 32 || s.Port < 1024 || s.Port > 65535 || s.Version != version || s.Created > time.Now().Unix()+5 || s.Created < time.Now().Add(-2*time.Minute).Unix() {
		return s, errors.New("desktop session expired or belongs to another version")
	}
	return s, nil
}
