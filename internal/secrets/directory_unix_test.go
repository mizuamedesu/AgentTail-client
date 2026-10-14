// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectReplaceableSecretDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned negative permission fixture")
	}
	base := t.TempDir()
	parent := filepath.Join(base, "foreign-parent")
	leaf := filepath.Join(parent, "root-owned-leaf")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := New(leaf); err == nil {
		t.Fatal("a foreign parent can replace the protected leaf")
	}
	link := filepath.Join(base, "root-owned-link")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(link, "root-owned-leaf")); err == nil {
		t.Fatal("symlink concealed a replaceable parent")
	}
}
