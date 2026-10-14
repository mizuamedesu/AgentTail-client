// SPDX-License-Identifier: GPL-3.0-or-later

// Package sshkeys installs OpenSSH identities for the invoking OS user. It does
// not load machine VPN credentials or account/vault credentials.
package sshkeys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func Public(value string) (ssh.PublicKey, error) {
	k, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil || k.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) != value {
		return nil, errors.New("expected a canonical ssh-ed25519 public key without options or comments")
	}
	return k, nil
}

func directory(home string) (*os.Root, error) {
	if !filepath.IsAbs(home) {
		return nil, errors.New("SSH home must be absolute")
	}
	h, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	if err = h.Mkdir(".ssh", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	i, err := h.Lstat(".ssh")
	if err != nil {
		return nil, err
	}
	if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New(".ssh must be a real directory")
	}
	if err = owned(i); err != nil {
		return nil, err
	}
	if err = protect(filepath.Join(home, ".ssh"), true); err != nil {
		return nil, err
	}
	return h.OpenRoot(".ssh")
}

func InstallPublic(home, public string) (string, error) {
	r, err := directory(home)
	if err != nil {
		return "", err
	}
	defer r.Close()
	return installAuthorized(r, filepath.Join(home, ".ssh"), "authorized_keys", public, protect)
}
func installAuthorized(r *os.Root, base, name, public string, permissions func(string, bool) error) (string, error) {
	key, err := Public(public)
	if err != nil {
		return "", err
	}
	if info, e := r.Lstat(name); e == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("authorized_keys must be a regular file, not a link")
		}
		if e = owned(info); e != nil {
			return "", e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	f, err := r.OpenFile(name, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if err = owned(info); err != nil {
		return "", err
	}
	listed, err := r.Lstat(name)
	if err != nil || !os.SameFile(info, listed) || !listed.Mode().IsRegular() {
		return "", errors.New("authorized_keys changed during installation")
	}
	if err = lock(f); err != nil {
		return "", err
	}
	path := filepath.Join(base, name)
	if err = permissions(path, false); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return "", err
	}
	if len(raw) > 1024*1024 {
		return "", errors.New("authorized_keys is too large")
	}
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		k, _, _, _, e := ssh.ParseAuthorizedKey(line)
		// Preserve restrictions on an existing entry; never add an unrestricted
		// duplicate of a key already authorized with forced-command options.
		if e == nil && bytes.Equal(k.Marshal(), key.Marshal()) {
			return path, nil
		}
	}
	entry := public + " AgentTail\n"
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		entry = "\n" + entry
	}
	if _, err = f.WriteString(entry); err != nil {
		return "", err
	}
	return path, f.Sync()
}

func InstallPrivate(home, id, expected string, seed []byte) (string, error) {
	if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id || len(seed) != ed25519.SeedSize {
		return "", errors.New("invalid SSH key ID or seed")
	}
	key, err := Public(expected)
	if err != nil {
		return "", err
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	pub, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return "", err
	}
	if !bytes.Equal(key.Marshal(), pub.Marshal()) {
		return "", errors.New("SSH private key does not match the selected public key")
	}
	r, err := directory(home)
	if err != nil {
		return "", err
	}
	defer r.Close()
	name := "agenttail_" + id
	// Exclusive creation: never truncate an existing identity, follow a link,
	// or overwrite a user's key with a second approval.
	f, err := r.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			r.Remove(name)
		}
	}()
	path := filepath.Join(home, ".ssh", name)
	if err = protect(path, false); err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(private, "AgentTail "+id)
	if err != nil {
		return "", err
	}
	defer clear(block.Bytes)
	raw := pem.EncodeToMemory(block)
	defer clear(raw)
	if _, err = f.Write(raw); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	complete = true
	return path, nil
}
