// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux && !riscv64

package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxFallbackWithoutSystemdAndProviderPersistence(t *testing.T) {
	s := hostStore(t)
	name := s.name("key/fallback")
	if err := s.linuxPut(name, []byte(`{"token":"fixture"}`), ""); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := s.Get("key/fallback", &got); err != nil || got["token"] != "fixture" {
		t.Fatalf("read without systemd: %v", err)
	}
	// Adding systemd later must preserve the existing host credential provider.
	if err := s.linuxPut(name, []byte(`{"token":"updated"}`), "/nonexistent/systemd-creds"); err != nil {
		t.Fatal(err)
	}
	if err := s.Get("key/fallback", &got); err != nil || got["token"] != "updated" {
		t.Fatalf("after upgrade: %v", err)
	}
	if err := s.Purge(); err == nil {
		t.Fatal("purged a host key while credentials remain")
	}
	if err := s.Delete("key/fallback"); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, hostKeyFile)); !os.IsNotExist(err) {
		t.Fatal("host key retained after purge")
	}
}

func TestLinuxFallbackNeverOverwritesUnreadableSystemdCredential(t *testing.T) {
	s := hostStore(t)
	name := s.name("key/existing-systemd")
	path := filepath.Join(s.Dir, name+".cred")
	sealed := []byte("existing-systemd-encrypted-credential-fixture")
	if err := os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.linuxPut(name, []byte("replacement"), ""); err == nil {
		t.Fatal("overwrote systemd ciphertext without its provider")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, sealed) {
		t.Fatal("existing credential changed")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, hostKeyFile)); !os.IsNotExist(err) {
		t.Fatal("created a replacement wrapping key")
	}
}
