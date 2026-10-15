// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func (m *Manager) desktopShortcut(record *DesktopRecord, add bool) error {
	base, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return err
	}
	production, _, err := locations()
	if err != nil {
		return err
	}
	if m.Root != production {
		base = filepath.Join(m.Root, "desktop-links")
	}
	if err = os.MkdirAll(base, 0755); err != nil {
		return err
	}
	entry := filepath.Join(base, "AgentTail.lnk")
	if info, e := os.Lstat(entry); e == nil && !info.Mode().IsRegular() {
		return errors.New("existing desktop shortcut is not a regular file")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	} else if errors.Is(e, os.ErrNotExist) && !add {
		return nil
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	target := desktopExecutable(filepath.Join(m.desktopRoot(), "releases", record.ReleaseID))
	script := "$ErrorActionPreference='Stop';$shell=New-Object -ComObject WScript.Shell;$link=" + quote(entry) + ";if(Test-Path -LiteralPath $link){$old=$shell.CreateShortcut($link);if(-not $old.TargetPath.StartsWith(" + quote(filepath.Join(m.desktopRoot(), "releases")+string(os.PathSeparator)) + ",[StringComparison]::OrdinalIgnoreCase)){throw 'Existing shortcut is not managed by AgentTail'}};"
	if !add {
		script = strings.ReplaceAll(script, "throw 'Existing shortcut is not managed by AgentTail'", "exit 0")
	}
	if add {
		script += "$shortcut=$shell.CreateShortcut($link);$shortcut.TargetPath=" + quote(target) + ";$shortcut.WorkingDirectory=" + quote(m.Root) + ";$shortcut.Description='AgentTail VPN manager';$shortcut.Save()"
	} else {
		script += "Remove-Item -LiteralPath $link"
	}
	encoded := utf16.Encode([]rune(script))
	raw := make([]byte, len(encoded)*2)
	for i, v := range encoded {
		raw[2*i] = byte(v)
		raw[2*i+1] = byte(v >> 8)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	command := exec.Command(filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	if output, err := command.CombinedOutput(); err != nil {
		return errors.New("desktop shortcut could not be updated: " + strings.TrimSpace(string(output)))
	}
	return nil
}
