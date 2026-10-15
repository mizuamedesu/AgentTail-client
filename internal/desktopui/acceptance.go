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
func (c *fixtureControl) Remove(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, v := range c.vpns {
		if v.ID == id {
			c.vpns = append(c.vpns[:i], c.vpns[i+1:]...)
			break
		}
	}
	return nil
}

// RunAcceptanceWindow uses the real native window and event loop with fixture
// data. It never opens the privileged helper or contacts a control server.
func RunAcceptanceWindow(application fyne.App, version, path string) {
	control := &fixtureControl{vpns: []desktop.VPN{
		{ID: "00000000-0000-4000-8000-000000000001", Name: "Office", State: "up", Desired: "up", Address: "10.40.0.2", Mode: "native", Peers: 1, BytesRead: 8 * 1024 * 1024},
		{ID: "00000000-0000-4000-8000-000000000002", Name: "Development", State: "down", Desired: "down", Mode: "native"},
	}}
	w := New(application, control)
	awaitUI := func(check func() bool, message string) {
		deadline := time.Now().Add(5 * time.Second)
		for {
			ready := false
			fyne.DoAndWait(func() { ready = check() })
			if ready {
				return
			}
			if time.Now().After(deadline) {
				panic(message)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
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
		awaitUI(func() bool { return w.button.Text == "Disconnect" }, "native VPN state did not refresh")
		fyne.DoAndWait(func() {
			control.mu.Lock()
			if w.selected != control.vpns[1].ID || w.button.Text != "Disconnect" || control.vpns[1].Desired != "up" || control.vpns[0].Desired != "up" {
				panic("native window changed the wrong VPN or failed to refresh")
			}
			control.mu.Unlock()
			w.remove.OnTapped()
			w.confirmation.Dismiss()
			if len(w.items) != 2 {
				panic("cancelled removal changed the VPN list")
			}
			w.remove.OnTapped()
			w.confirmation.Confirm()
		})
		awaitUI(func() bool { return len(w.items) == 1 }, "native VPN removal did not refresh")
		fyne.DoAndWait(func() {
			if len(w.items) != 1 || w.name.Text != "Office" || w.button.Text != "Disconnect" {
				panic("removal changed another VPN or failed to refresh")
			}
			w.remove.OnTapped()
			w.confirmation.Confirm()
		})
		awaitUI(func() bool { return len(w.items) == 0 }, "native final VPN removal did not refresh")
		fyne.DoAndWait(func() {
			if len(w.items) != 0 || w.empty.Hidden || !w.panel.Hidden {
				panic("removing the final VPN did not show the empty state")
			}
			proof := map[string]any{"version": version, "native_window_started": true, "selection_scope": true, "other_vpn_preserved": true, "state_refreshed": true, "removal_cancelled": true, "selected_vpn_removed": true, "last_vpn_empty_state": true, "fixture_only": true}
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
