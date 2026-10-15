// SPDX-License-Identifier: GPL-3.0-or-later

//go:build desktop

package desktopui

import (
	"context"
	"image/png"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"github.com/mizuamedesu/AgentTail-client/internal/desktop"
)

type controls struct {
	mu    sync.Mutex
	calls []desktop.Action
}

func (*controls) Status(context.Context) (desktop.Snapshot, error) { return desktop.Snapshot{}, nil }
func (c *controls) Toggle(ctx context.Context, id, action string) error {
	c.mu.Lock()
	c.calls = append(c.calls, desktop.Action{ID: id, Action: action})
	c.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}
func (*controls) StartService(context.Context) error            { return nil }
func (c *controls) Remove(ctx context.Context, id string) error { return c.Toggle(ctx, id, "leave") }

func TestWindowSelectsAndControlsOnlyTheSelectedVPN(t *testing.T) {
	application := test.NewApp()
	defer application.Quit()
	control := &controls{}
	w := New(application, control)
	defer w.cancel()
	state := desktop.Snapshot{Version: "test", Running: true, VPNs: []desktop.VPN{
		{ID: "00000000-0000-4000-8000-000000000001", Name: "Office", State: "up", Desired: "up", Address: "10.40.0.2", Mode: "native", Peers: 1, BytesRead: 8 * 1024 * 1024},
		{ID: "00000000-0000-4000-8000-000000000002", Name: "Development", State: "down", Desired: "down", Mode: "native"},
	}}
	w.apply(state)
	// Export a reviewable rendering of the actual window, with fixture names.
	if destination := os.Getenv("AGENTTAIL_DESKTOP_SCREENSHOT"); destination != "" {
		w.apply(state)
		w.list.Select(0)
		w.window.Resize(fyne.NewSize(740, 480))
		w.window.Content().Refresh()
		if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(destination)
		if err != nil {
			t.Fatal(err)
		}
		if err = png.Encode(file, w.window.Canvas().Capture()); err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
	}
	if w.button.Text != "Disconnect" {
		t.Fatal("connected VPN cannot be disconnected")
	}
	w.list.Select(1)
	if w.button.Text != "Connect" {
		t.Fatal("selection did not update its action")
	}
	test.Tap(w.button)
	deadline := time.Now().Add(3 * time.Second)
	for {
		control.mu.Lock()
		calls := append([]desktop.Action{}, control.calls...)
		control.mu.Unlock()
		if len(calls) == 1 {
			if calls[0] != (desktop.Action{ID: state.VPNs[1].ID, Action: "up"}) {
				t.Fatalf("wrong VPN/action: %+v", calls)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("selected VPN was not activated")
		}
		time.Sleep(5 * time.Millisecond)
	}
	w.list.Select(0)
	if w.button.Disabled() || w.button.Text != "Disconnect" {
		t.Fatal("an in-flight action blocked a different VPN")
	}

}

func TestRemovalRequiresConfirmationAndKeepsTheConfirmedTarget(t *testing.T) {
	application := test.NewApp()
	defer application.Quit()
	control := &controls{}
	w := New(application, control)
	defer w.cancel()
	state := desktop.Snapshot{Running: false, VPNs: []desktop.VPN{
		{ID: "00000000-0000-4000-8000-000000000001", Name: "Office", Desired: "up"},
		{ID: "00000000-0000-4000-8000-000000000002", Name: "Development", Desired: "down"},
	}}
	w.apply(state)
	w.list.Select(1)
	if w.remove.Disabled() {
		t.Fatal("a stopped service must not prevent VPN removal")
	}
	test.Tap(w.remove)
	if w.confirmation == nil {
		t.Fatal("removal did not ask for confirmation")
	}
	w.confirmation.Dismiss()
	control.mu.Lock()
	called := len(control.calls)
	control.mu.Unlock()
	if called != 0 {
		t.Fatal("cancelling removal changed a VPN")
	}
	test.Tap(w.remove)
	// Background refresh/selection must not change which VPN was confirmed.
	w.list.Select(0)
	w.confirmation.Confirm()
	deadline := time.Now().Add(3 * time.Second)
	for {
		control.mu.Lock()
		calls := append([]desktop.Action{}, control.calls...)
		control.mu.Unlock()
		if len(calls) == 1 {
			if calls[0] != (desktop.Action{ID: state.VPNs[1].ID, Action: "leave"}) {
				t.Fatalf("wrong removal target: %+v", calls)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("confirmed VPN was not removed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if w.remove.Disabled() {
		t.Fatal("removing another VPN blocked this VPN")
	}
	w.list.Select(1)
	if !w.remove.Disabled() {
		t.Fatal("an in-flight removal can be submitted again")
	}
}
