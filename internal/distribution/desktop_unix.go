// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package distribution

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func (m *Manager) desktopShortcut(record *DesktopRecord, add bool) error {
	root := filepath.Join(m.desktopRoot(), "releases", record.ReleaseID)
	production, _, err := locations()
	if err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		entry := "/Applications/AgentTail.app"
		if m.Root != production {
			entry = filepath.Join(m.Root, "desktop-links", "AgentTail.app")
		}
		if info, e := os.Lstat(entry); e == nil {
			if info.Mode()&os.ModeSymlink == 0 {
				if !add {
					return nil
				}
				return errors.New("existing AgentTail application is not managed by this installer")
			}
			target, e := os.Readlink(entry)
			if e != nil {
				return e
			}
			if !strings.HasPrefix(filepath.Clean(target), filepath.Join(m.desktopRoot(), "releases")+string(os.PathSeparator)) {
				if !add {
					return nil
				}
				return errors.New("existing AgentTail application link belongs to another installation")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else if !add {
			return nil
		}
		if !add {
			return os.Remove(entry)
		}
		if err = os.MkdirAll(filepath.Dir(entry), 0755); err != nil {
			return err
		}
		f, e := os.CreateTemp(filepath.Dir(entry), ".agenttail-app-")
		if e != nil {
			return e
		}
		temp := f.Name()
		_ = f.Close()
		_ = os.Remove(temp)
		defer os.Remove(temp)
		if err = os.Symlink(filepath.Join(root, "AgentTail.app"), temp); err != nil {
			return err
		}
		return os.Rename(temp, entry)
	}
	entry := "/usr/share/applications/io.agenttail.desktop"
	if m.Root != production {
		entry = filepath.Join(m.Root, "desktop-links", "io.agenttail.desktop")
	}
	marker := "# AgentTail managed desktop entry\n"
	if info, e := os.Lstat(entry); e == nil {
		if !info.Mode().IsRegular() {
			if !add {
				return nil
			}
			return errors.New("existing desktop entry is not a regular file")
		}
		data, e := os.ReadFile(entry)
		if e != nil {
			return e
		}
		if !strings.HasPrefix(string(data), marker) {
			if !add {
				return nil
			}
			return errors.New("existing desktop entry is not managed by AgentTail")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	} else if !add {
		return nil
	}
	if !add {
		return os.Remove(entry)
	}
	// A desktop entry launches the unprivileged window. Shared menu folders
	// may be group- or user-managed; preserve their ownership and permissions.
	// Privileged executables remain under the separately validated install root.
	parent := filepath.Dir(entry)
	if info, e := os.Lstat(parent); errors.Is(e, os.ErrNotExist) {
		if err = os.MkdirAll(parent, 0755); err != nil {
			return err
		}
		if err = os.Chmod(parent, 0755); err != nil {
			return err
		}
	} else if e != nil {
		return e
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("desktop menu path is not a directory")
	}
	content := fmt.Sprintf("%s[Desktop Entry]\nType=Application\nName=AgentTail\nComment=Connect and disconnect your VPNs\nExec=%s\nIcon=%s\nTerminal=false\nCategories=Network;\nStartupWMClass=AgentTail\n", marker, strconv.Quote(desktopExecutable(root)), filepath.Join(root, "agenttail.svg"))
	return atomicFile(entry, []byte(content), 0644)
}
