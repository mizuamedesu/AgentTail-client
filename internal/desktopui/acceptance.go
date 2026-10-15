// SPDX-License-Identifier: GPL-3.0-or-later

//go:build desktop && acceptance

package desktopui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"github.com/mizuamedesu/AgentTail-client/internal/desktop"
)

type fixtureControl struct {
	mu   sync.Mutex
	vpns []desktop.VPN
}

func (c *fixtureControl) Status(context.Context) (desktop.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return desktop.Snapshot{Running: true, VPNs: append([]desktop.VPN{}, c.vpns...)}, nil
}
func (c *fixtureControl) Toggle(_ context.Context, id, action string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, v := range c.vpns {
		if v.ID == id {
			c.vpns[i].Desired = action
			c.vpns[i].State = action
		}
	}
	return nil
}
func (*fixtureControl) StartService(context.Context) error { return nil }

// RunAcceptanceWindow uses the real native window and event loop with fixture
// data. It never opens the privileged helper or contacts a control server.
func RunAcceptanceWindow(application fyne.App, version, path string) {
	control := &fixtureControl{vpns: []desktop.VPN{
		{ID: "00000000-0000-4000-8000-000000000001", Name: "Office", State: "up", Desired: "up", Address: "10.40.0.2", Mode: "native", Peers: 1, BytesRead: 8 * 1024 * 1024},
		{ID: "00000000-0000-4000-8000-000000000002", Name: "Development", State: "down", Desired: "down", Mode: "native"},
	}}
	w := New(application, control)
	go func() {
		time.Sleep(4 * time.Second)
		fyne.DoAndWait(func() {
			if len(w.items) != 2 || w.name.Text != "Office" || w.button.Text != "Disconnect" {
				panic("native VPN list did not initialize")
			}
			w.list.Select(1)
			if w.button.Text != "Connect" {
				panic("selection did not change the VPN action")
			}
			w.button.OnTapped()
		})
		time.Sleep(2 * time.Second)
		fyne.DoAndWait(func() {
			control.mu.Lock()
			defer control.mu.Unlock()
			if w.selected != control.vpns[1].ID || w.button.Text != "Disconnect" || control.vpns[1].Desired != "up" || control.vpns[0].Desired != "up" {
				panic("native window changed the wrong VPN or failed to refresh")
			}
			proof := map[string]any{"version": version, "native_window_started": true, "selection_scope": true, "other_vpn_preserved": true, "state_refreshed": true, "fixture_only": true}
			data, err := json.MarshalIndent(proof, "", "  ")
			if err != nil {
				panic(err)
			}
			if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				panic(err)
			}
			if err = os.WriteFile(path, append(data, '\n'), 0644); err != nil {
				panic(err)
			}
			w.Close()
		})
	}()
	w.ShowAndRun()
}
