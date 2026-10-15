// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/windows"
)

func InstalledCLI(version string) (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	root := filepath.Join(base, "AgentTail")
	data, err := os.ReadFile(filepath.Join(root, "installation.json"))
	if err != nil {
		return "", errors.New("install AgentTail before opening the VPN manager")
	}
	var record struct {
		Version   string `json:"version"`
		ReleaseID string `json:"release_id"`
	}
	if json.Unmarshal(data, &record) != nil || record.Version != version || !regexp.MustCompile("^"+regexp.QuoteMeta(version)+"-[a-f0-9]{16}$").MatchString(record.ReleaseID) {
		return "", errors.New("reinstall AgentTail to update the desktop and service together")
	}
	return filepath.Join(root, "releases", record.ReleaseID, "vpn.exe"), nil
}

func OpenWindow() error {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	path, err := windowExecutable(filepath.Join(base, "AgentTail"))
	if err != nil {
		return err
	}
	command := exec.Command(path)
	if err = command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}

func installedRoot() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "AgentTail"), nil
}
