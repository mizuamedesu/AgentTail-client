// SPDX-License-Identifier: GPL-3.0-or-later

package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectionPreservesExistingSkills(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0700); err != nil {
		t.Fatal(err)
	}
	result, err := installAt(home, func(n string) bool { return n == "claude" })
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || result[0].Status != "installed" || result[1].Status != "installed" {
		t.Fatal(result)
	}
	path := filepath.Join(home, ".agents", "skills", "agenttail-vpn", "SKILL.md")
	os.WriteFile(path, []byte("user customized skill"), 0600)
	result, err = installAt(home, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "user customized skill" || result[0].Status != "preserved_existing" {
		t.Fatal("existing skill was changed")
	}
}
func TestSymlinkAndAbsentAgent(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	result, err := installAt(home, func(string) bool { return false })
	if err != nil || result[0].Status != "not_detected" {
		t.Fatal(result, err)
	}
	if err = os.Symlink(other, filepath.Join(home, ".agents")); err != nil {
		t.Skip("symlink privilege unavailable")
	}
	if _, err = installAt(home, func(string) bool { return true }); err == nil {
		t.Fatal("symlink followed")
	}
	files, _ := os.ReadDir(other)
	if len(files) != 0 {
		t.Fatal("wrote outside skill directory")
	}
}
