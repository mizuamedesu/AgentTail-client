// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package distribution

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (m *Manager) desktopShortcut(record *DesktopRecord, add bool) error {
	root := filepath.Join(m.desktopRoot(), "releases", record.ReleaseID)
	production, _, err := locations()
	if err != nil {
		return err
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
