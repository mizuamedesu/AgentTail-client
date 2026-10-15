// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/platform"
)

// Launch asks the OS to authorize a narrowly scoped helper. The window and its
// URL-opening code stay under the signed-in user's ordinary permissions.
func Launch(ctx context.Context, version string) (*Client, func(), error) {
	executable, err := InstalledCLI(version)
	if err != nil {
		return nil, nil, err
	}
	if info, err := os.Stat(executable); err != nil || !info.Mode().IsRegular() {
		return nil, nil, errors.New("install AgentTail before opening the VPN manager")
	}
	root, err := installedRoot()
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(filepath.Join(root, "installation.json"))
	if err != nil {
		return nil, nil, errors.New("install AgentTail before opening the VPN manager")
	}
	var record struct {
		Version  string `json:"version"`
		StateDir string `json:"state_dir"`
	}
	if json.Unmarshal(data, &record) != nil || record.Version != version || !filepath.IsAbs(record.StateDir) {
		return nil, nil, errors.New("reinstall AgentTail to update the desktop and service together")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	session, path, cleanup, err := NewSession(port, version)
	if err != nil {
		return nil, nil, err
	}
	if err = platform.StartDesktopHelper(executable, path, record.StateDir); err != nil {
		cleanup()
		return nil, nil, err
	}
	client := NewClient(session)
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if _, err = client.Status(deadline); err == nil {
			_ = os.Remove(path)
			return client, cleanup, nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-deadline.Done():
			timer.Stop()
			cleanup()
			return nil, nil, errors.New("VPN management could not be authorized; reopen AgentTail and approve the OS prompt")
		case <-timer.C:
		}
	}
}
