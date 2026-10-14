// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package distribution

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEnsureLauncherRepairsPublicDirectoryAccess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires installer privileges")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Root: filepath.Join(parent, "AgentTail")}
	m.Launcher = filepath.Join(m.Root, "agenttail")
	r := &Record{ReleaseID: "test-release"}
	if err := os.MkdirAll(filepath.Dir(m.executable(r)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.executable(r), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(m.executable(r), m.Launcher); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{m.Root, filepath.Join(m.Root, "releases")} {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.ensureLauncher(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{m.Root, filepath.Join(m.Root, "releases")} {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatalf("public directory was not repaired: %s (%v)", dir, err)
		}
	}
	info, err := os.Stat(parent)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("changed the private ancestor's permissions")
	}
}

// Run the restrictive umask in a child: umask is process-wide and must not
// affect other tests or unrelated goroutines in the parent Go test process.
func TestInstallDirectoryWithPrivateUmask(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native lifecycle CI also checks this under an elevated installer")
	}
	if os.Getenv("AGENTTAIL_TEST_INSTALL_UMASK") == "1" {
		syscall.Umask(0077)
		root := filepath.Join(t.TempDir(), "AgentTail")
		for _, path := range []string{root, filepath.Join(root, "releases")} {
			if err := secureInstallDirectory(path); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0755 {
				t.Fatalf("public install directory has mode %04o under umask 077; users cannot find the CLI", info.Mode().Perm())
			}
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := secureInstallDirectory(path); err != nil {
				t.Fatal(err)
			}
			info, _ = os.Stat(path)
			if info.Mode().Perm() != 0755 {
				t.Fatal("existing private install directory was not repaired")
			}
		}
		return
	}
	args := []string{os.Args[0], "-test.run=^TestInstallDirectoryWithPrivateUmask$"}
	// go test -exec only wraps the parent test binary. Containers without
	// binfmt_misc also need the explicit emulator for this child process.
	if runner := os.Getenv("AGENTTAIL_TEST_RUNNER"); runner != "" {
		args = append([]string{runner}, args...)
	}
	command := exec.Command(args[0], args[1:]...)
	command.Env = append(os.Environ(), "AGENTTAIL_TEST_INSTALL_UMASK=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("restrictive-umask installer: %v\n%s", err, output)
	}
}

func TestInstallDirectoryRejectsUnsafePathsBeforeChangingModes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires installer privileges")
	}
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "AgentTail")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := secureInstallDirectory(link); err == nil {
		t.Fatal("symlink install directory accepted")
	}
	info, _ := os.Stat(outside)
	if info.Mode().Perm() != 0700 {
		t.Fatal("modified the symlink target")
	}
	unsafe := filepath.Join(root, "writable")
	if err := os.Mkdir(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if err := secureInstallDirectory(unsafe); err == nil {
		t.Fatal("untrusted writable install directory accepted")
	}
}
