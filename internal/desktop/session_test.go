// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestDesktopSessionExpiryAndPermissions(t *testing.T) {
	s, path, cleanup, err := NewSession(18939, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, err := ReadSession(path, "test"); err != nil || got.Secret != s.Secret {
		t.Fatalf("valid session rejected: %v", err)
	}
	if _, err := ReadSession(path, "other"); err == nil {
		t.Fatal("different GUI version accepted")
	}
	s.Created = time.Now().Add(-3 * time.Minute).Unix()
	data, _ := json.Marshal(s)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSession(path, "test"); err == nil {
		t.Fatal("expired session accepted")
	}
	if runtime.GOOS != "windows" {
		s.Created = time.Now().Unix()
		data, _ = json.Marshal(s)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSession(path, "test"); err == nil {
			t.Fatal("world-readable capability accepted")
		}
	}
}
