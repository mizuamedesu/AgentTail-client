// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

func windowExecutable(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "desktop", "installation.json"))
	if err != nil {
		return "", errors.New("the VPN manager is not installed; run agenttail gui install")
	}
	var record struct {
		Version   string `json:"version"`
		ReleaseID string `json:"release_id"`
		SHA256    string `json:"sha256"`
	}
	if json.Unmarshal(data, &record) != nil || !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?-[a-f0-9]{16}$`).MatchString(record.ReleaseID) || len(record.SHA256) != 64 || record.ReleaseID != record.Version+"-"+record.SHA256[:16] {
		return "", errors.New("invalid desktop installation record")
	}
	name := "agenttail-desktop"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(root, "desktop", "releases", record.ReleaseID, name), nil
}
