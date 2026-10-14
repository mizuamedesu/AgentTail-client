// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package distribution

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func locations() (string, string, error) {
	// Homebrew may own /usr/local on macOS. A root daemon must live under
	// administrator-controlled ancestors independent of a package manager.
	if runtime.GOOS == "darwin" {
		return "/Library/AgentTail", "/Library/AgentTail/agenttail", nil
	}
	return "/usr/local/lib/agenttail", "/usr/local/lib/agenttail/agenttail", nil
}
func secureInstallDirectory(path string) error {
	if !filepath.IsAbs(path) || os.Geteuid() != 0 {
		return errors.New("install directory requires root and an absolute path")
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 && !(p != path && info.Mode()&os.ModeSticky != 0) {
			return fmt.Errorf("install directory ancestor %s must be root-owned and not writable by other users", p)
		}
		if p == "/" {
			break
		}
	}
	// The bootstrap deliberately uses umask 077 to protect temporary files.
	// These directories contain public executables: ordinary users must be
	// able to traverse them before the CLI can request elevation. Set only
	// this validated install directory, never its ancestors or private state.
	return os.Chmod(path, 0755)
}
func (m *Manager) ownsLauncher() (bool, error) {
	i, err := os.Lstat(m.Launcher)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if i.Mode()&os.ModeSymlink == 0 {
		return false, errUnmanagedLauncher
	}
	target, err := os.Readlink(m.Launcher)
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(filepath.Clean(target), filepath.Join(m.Root, "releases")+string(os.PathSeparator)) {
		return false, errUnmanagedLauncher
	}
	return true, nil
}
func (m *Manager) activate(r *Record) error {
	if err := secureInstallDirectory(filepath.Dir(m.Launcher)); err != nil {
		return err
	}
	if _, err := m.ownsLauncher(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(m.Launcher), ".agenttail-link-")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	defer os.Remove(name)
	if err = os.Symlink(m.executable(r), name); err != nil {
		return err
	}
	if err = os.Rename(name, m.Launcher); err != nil {
		return err
	}
	return m.pathEntry(true)
}
func (m *Manager) removeLauncher() error {
	exists, err := m.ownsLauncher()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err = os.Remove(m.Launcher); err != nil {
		return err
	}
	return m.pathEntry(false)
}
func (m *Manager) pathEntry(add bool) error {
	// Unit tests use an isolated launcher. Production always uses this path.
	_, expectedLauncher, _ := locations()
	if m.Launcher != expectedLauncher {
		return nil
	}
	path := "/etc/profile.d/agenttail.sh"
	data := "# AgentTail managed PATH entry\ncase :$PATH: in *:/usr/local/lib/agenttail:*) ;; *) export PATH=\"/usr/local/lib/agenttail:$PATH\" ;; esac\n"
	if runtime.GOOS == "darwin" {
		path = "/etc/paths.d/agenttail"
		data = "/Library/AgentTail\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("existing PATH configuration is not a regular file")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if string(b) != data {
			return errors.New("existing PATH configuration is not managed by AgentTail")
		}
		if add {
			return nil
		}
		return os.Remove(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !add {
		return nil
	}
	return atomicFile(path, []byte(data), 0644)
}
func (m *Manager) serviceExecutable(*Record) string { return m.Launcher }
func removeReleaseTree(dir string) (bool, error)    { return false, os.RemoveAll(dir) }
