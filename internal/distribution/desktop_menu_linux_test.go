// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDesktopMenuPreservesSharedFolderOwnershipAndPermissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		uid  int
	}{{"shared group", 0775, 0}, {"desktop owner", 0755, 1000}} {
		t.Run(tc.name, func(t *testing.T) {
			if os.Geteuid() != 0 {
				t.Skip("fixture ownership requires root")
			}
			m := &Manager{Root: t.TempDir()}
			parent := filepath.Join(m.Root, "desktop-links")
			if err := os.Mkdir(parent, tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(parent, tc.uid, tc.uid); err != nil {
				t.Fatal(err)
			}
			r := &DesktopRecord{Version: "0.1.0-test", SHA256: strings.Repeat("a", 64), ReleaseID: "0.1.0-test-" + strings.Repeat("a", 16)}
			if err := m.desktopShortcut(r, true); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(parent)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != tc.mode || int(info.Sys().(*syscall.Stat_t).Uid) != tc.uid {
				t.Fatal("shared desktop directory was modified")
			}
			if err := m.desktopShortcut(r, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRemovePendingDesktopLeavesOtherMenuEntries(t *testing.T) {
	m := &Manager{Root: t.TempDir()}
	if err := os.MkdirAll(m.desktopRoot(), 0755); err != nil {
		t.Fatal(err)
	}
	r := &DesktopRecord{Version: "0.1.0-test", SHA256: strings.Repeat("a", 64), ReleaseID: "0.1.0-test-" + strings.Repeat("a", 16)}
	data, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(m.desktopRoot(), "pending.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(m.Root, "desktop-links")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(parent, "io.agenttail.desktop")
	if err := os.WriteFile(entry, []byte("another application's entry\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveDesktop(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(entry); err != nil || string(got) != "another application's entry\n" {
		t.Fatal("unmanaged menu entry changed")
	}
	if _, err := os.Stat(m.desktopRoot()); !os.IsNotExist(err) {
		t.Fatal("interrupted desktop installation remains")
	}
}
