// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package distribution

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDesktopExecutableReadableAfterPrivateBootstrapUmask(t *testing.T) {
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	root := t.TempDir()
	if err := extractDesktop(desktopTar(t, nil), root, "linux"); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"agenttail-desktop": 0755, "GPL-3.0.txt": 0644, "THIRD_PARTY_NOTICES.txt": 0644, "agenttail.svg": 0644} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s is inaccessible to the desktop user: %o", name, info.Mode().Perm())
		}
	}
}
