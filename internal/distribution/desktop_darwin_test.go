// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func macDesktopFixture(t *testing.T, m *Manager, version, digest string) *DesktopRecord {
	t.Helper()
	r := &DesktopRecord{Version: version, ReleaseID: version + "-" + digest[:16], SHA256: digest}
	app := filepath.Join(m.desktopRoot(), "releases", r.ReleaseID, "AgentTail.app")
	for name, contents := range map[string]string{
		"Contents/MacOS/agenttail-desktop":      version,
		"Contents/Info.plist":                   "signed application metadata " + version,
		"Contents/_CodeSignature/CodeResources": "signed resources " + version,
	} {
		path := filepath.Join(app, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0644)
		if strings.Contains(name, "MacOS/") {
			mode = 0755
		}
		if err := os.WriteFile(path, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func TestMacDesktopApplicationMigratesLinkAndUpdatesRealBundle(t *testing.T) {
	m := &Manager{Root: t.TempDir()}
	old := macDesktopFixture(t, m, "1.2.3", strings.Repeat("1", 64))
	next := macDesktopFixture(t, m, "1.2.4", strings.Repeat("2", 64))
	third := macDesktopFixture(t, m, "1.2.5", strings.Repeat("3", 64))
	if err := writeJSON(filepath.Join(m.desktopRoot(), "installation.json"), old); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(m.Root, "desktop-links", "AgentTail.app")
	if err := os.MkdirAll(filepath.Dir(entry), 0755); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(m.desktopRoot(), "releases", old.ReleaseID, "AgentTail.app")
	if err := os.Symlink(legacy, entry); err != nil {
		t.Fatal(err)
	}
	umask := syscall.Umask(0077)
	defer syscall.Umask(umask)
	for _, record := range []*DesktopRecord{next, next, third} {
		if err := m.desktopShortcut(record, true); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(entry)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("application menu entry is not a real bundle: %v, %v", info, err)
		}
		got, err := desktopApplicationDigest(entry)
		if err != nil {
			t.Fatal(err)
		}
		want, err := desktopApplicationDigest(filepath.Join(m.desktopRoot(), "releases", record.ReleaseID, "AgentTail.app"))
		if err != nil || got != want {
			t.Fatalf("published bundle does not match signed source: %v", err)
		}
		if err := writeJSON(filepath.Join(m.desktopRoot(), "installation.json"), record); err != nil {
			t.Fatal(err)
		}
	}
	if err := filepath.WalkDir(entry, func(path string, item os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		want := os.FileMode(0644)
		if item.IsDir() || strings.Contains(path, "/MacOS/") {
			want = 0755
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s has mode %o, want %o", path, info.Mode().Perm(), want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.desktopShortcut(third, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(entry); !os.IsNotExist(err) {
		t.Fatal("managed application was not removed")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("migration modified the old verified source bundle", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(entry), ".agenttail-app-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatal("application staging files left behind", leftovers, err)
	}
}

func TestMacDesktopApplicationPreservesUnmanagedEntries(t *testing.T) {
	for _, kind := range []string{"foreign-link", "foreign-directory", "modified-installed-bundle"} {
		t.Run(kind, func(t *testing.T) {
			m := &Manager{Root: t.TempDir()}
			r := macDesktopFixture(t, m, "1.2.3", strings.Repeat("1", 64))
			entry := filepath.Join(m.Root, "desktop-links", "AgentTail.app")
			if err := os.MkdirAll(filepath.Dir(entry), 0755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "foreign-link":
				if err := os.Symlink(t.TempDir(), entry); err != nil {
					t.Fatal(err)
				}
			case "foreign-directory":
				if err := os.Mkdir(entry, 0755); err != nil {
					t.Fatal(err)
				}
			case "modified-installed-bundle":
				if err := m.desktopShortcut(r, true); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(entry, "user-file"), []byte("preserve me"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(entry)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.desktopShortcut(r, true); err == nil {
				t.Fatal("overwrote an unmanaged application")
			}
			if err := m.desktopShortcut(r, false); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(entry)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("uninstall changed the unmanaged application", err)
			}
		})
	}
}
