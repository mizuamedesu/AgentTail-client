// SPDX-License-Identifier: GPL-3.0-or-later

//go:build desktop

package desktopui

import (
	"context"
	"fmt"
	"image/color"
	"net/url"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/mizuamedesu/AgentTail-client/internal/desktop"
	"github.com/mizuamedesu/AgentTail-client/internal/notices"
)

type Controller interface {
	Status(context.Context) (desktop.Snapshot, error)
	Toggle(context.Context, string, string) error
	Remove(context.Context, string) error
	StartService(context.Context) error
}

type Window struct {
	window                  fyne.Window
	client                  Controller
	ctx                     context.Context
	cancel                  context.CancelFunc
	mu                      sync.Mutex // serializes refreshes, not independent VPN operations
	items                   []desktop.VPN
	running                 bool
	selected                string
	busy                    map[string]bool
	list                    *widget.List
	name, problem, footer   *widget.Label
	detail                  *widget.Form
	fields                  map[string]*widget.Label
	state                   *canvas.Text
	button, remove, service *widget.Button
	panel, empty            *fyne.Container
	confirmation            *dialog.ConfirmDialog
}

func New(application fyne.App, client Controller) *Window {
	ctx, cancel := context.WithCancel(context.Background())
	w := &Window{window: application.NewWindow("AgentTail"), client: client, ctx: ctx, cancel: cancel, busy: map[string]bool{}}
	w.window.Resize(fyne.NewSize(740, 480))
	w.window.SetMaster()
	w.window.SetMainMenu(fyne.NewMainMenu(fyne.NewMenu("Help", fyne.NewMenuItem("Licenses and source", func() {
		text := widget.NewRichTextWithText("AgentTail · GPL-3.0-or-later\n" + notices.SourceURL + "\n\n" + notices.GPL + "\n\n" + notices.Desktop)
		view := container.NewVScroll(text)
		view.SetMinSize(fyne.NewSize(610, 350))
		dialog.ShowCustom("Licenses and source", "Close", view, w.window)
	}))))
	w.name = widget.NewLabelWithStyle("Select a VPN", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	w.name.TextStyle.Bold = true
	w.state = canvas.NewText("", theme.ForegroundColor())
	w.detail = widget.NewForm()
	w.fields = map[string]*widget.Label{}
	for _, key := range []string{"VPN IP", "Mode", "Peers", "Sent", "Received", "SOCKS5"} {
		w.fields[key] = widget.NewLabel("")
	}
	w.problem = widget.NewLabel("")
	w.problem.Wrapping = fyne.TextWrapWord
	w.footer = widget.NewLabel("Connecting to the local service…")
	w.footer.Wrapping = fyne.TextWrapWord
	w.button = widget.NewButton("Connect", w.toggle)
	w.button.Disable()
	w.remove = widget.NewButtonWithIcon("Remove VPN", theme.DeleteIcon(), w.removeVPN)
	w.remove.Importance = widget.DangerImportance
	w.remove.Disable()
	w.service = widget.NewButton("Start service", func() { w.work(func(ctx context.Context) error { return w.client.StartService(ctx) }) })
	w.service.Hide()
	w.list = widget.NewList(func() int { return len(w.items) }, func() fyne.CanvasObject {
		return container.NewVBox(widget.NewLabelWithStyle("VPN", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), widget.NewLabel("Disconnected"))
	}, func(id widget.ListItemID, object fyne.CanvasObject) {
		row := w.items[id]
		box := object.(*fyne.Container)
		box.Objects[0].(*widget.Label).SetText(row.Name)
		box.Objects[1].(*widget.Label).SetText(statusLabel(row))
	})
	w.list.OnSelected = func(id widget.ListItemID) {
		if id >= 0 && id < len(w.items) {
			w.selected = w.items[id].ID
			w.updateDetail()
		}
	}
	w.panel = container.NewBorder(container.NewVBox(w.name, w.state, widget.NewSeparator()), nil, nil, nil,
		container.NewVBox(w.detail, w.problem, container.NewHBox(w.button, layout.NewSpacer(), w.remove)))
	website := widget.NewButtonWithIcon("Manage VPNs", theme.ComputerIcon(), func() { target, _ := url.Parse("https://agenttail.mizuame.app"); _ = application.OpenURL(target) })
	w.empty = container.NewCenter(container.NewVBox(widget.NewLabelWithStyle("No VPNs on this device", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), widget.NewLabel("Add this device from your AgentTail VPN page."), website))
	w.empty.Hide()
	right := container.NewStack(container.NewPadded(w.panel), w.empty)
	split := container.NewHSplit(container.NewBorder(widget.NewLabelWithStyle("VPNs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), nil, nil, nil, w.list), right)
	split.Offset = 0.34
	refresh := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), w.Refresh)
	web := widget.NewButtonWithIcon("Manage VPNs", theme.ComputerIcon(), func() { target, _ := url.Parse("https://agenttail.mizuame.app"); _ = application.OpenURL(target) })
	header := container.NewBorder(nil, nil, widget.NewLabelWithStyle("AgentTail", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), container.NewHBox(web, refresh), nil)
	bottom := container.NewBorder(nil, nil, nil, w.service, w.footer)
	w.window.SetContent(container.NewPadded(container.NewBorder(container.NewVBox(header, widget.NewSeparator()), container.NewVBox(widget.NewSeparator(), bottom), nil, nil, split)))
	w.window.SetOnClosed(cancel)
	return w
}

func statusLabel(v desktop.VPN) string {
	if v.State == "stopped" {
		return "Service stopped"
	}
	if v.Desired != "up" {
		return "Disconnected"
	}
	if v.State == "up" {
		return "Connected"
	}
	if v.Problem == "CONFLICT" {
		return "Waiting for previous session"
	}
	if v.Problem != "" {
		return "Needs attention"
	}
	return "Connecting…"
}

func (w *Window) updateDetail() {
	for _, item := range w.items {
		if item.ID != w.selected {
			continue
		}
		w.name.SetText(item.Name)
		w.state.Text = statusLabel(item)
		w.state.Color = theme.ForegroundColor()
		if item.State == "up" && item.Desired == "up" {
			w.state.Color = color.NRGBA{R: 35, G: 145, B: 83, A: 255}
		}
		w.state.Refresh()
		address := item.Address
		if address == "" {
			address = "—"
		}
		w.fields["VPN IP"].SetText(address)
		w.fields["Mode"].SetText(item.Mode)
		w.fields["Peers"].SetText(fmt.Sprint(item.Peers))
		w.fields["Sent"].SetText(bytes(item.BytesSent))
		w.fields["Received"].SetText(bytes(item.BytesRead))
		w.detail.Items = nil
		for _, key := range []string{"VPN IP", "Mode", "Peers", "Sent", "Received"} {
			w.detail.Items = append(w.detail.Items, widget.NewFormItem(key, w.fields[key]))
		}
		if item.SOCKS5 != "" {
			w.fields["SOCKS5"].SetText(item.SOCKS5)
			w.detail.Items = append(w.detail.Items, widget.NewFormItem("SOCKS5", w.fields["SOCKS5"]))
		}
		w.detail.Refresh()
		w.problem.SetText(item.Problem)
		if item.Problem == "CONFLICT" {
			w.problem.SetText("The previous session may take up to 60 seconds to expire. AgentTail will retry automatically.")
		}
		action := "Connect"
		if item.Desired == "up" {
			action = "Disconnect"
		}
		if !w.running {
			w.button.Disable()
		} else if w.busy[item.ID] {
			action = "Applying…"
			w.button.Disable()
		} else {
			w.button.Enable()
		}
		w.button.SetText(action)
		if w.busy[item.ID] {
			w.remove.Disable()
		} else {
			w.remove.Enable()
		}
		return
	}
	w.name.SetText("Select a VPN")
	w.state.Text = ""
	w.state.Refresh()
	w.detail.Items = nil
	w.detail.Refresh()
	w.problem.SetText("")
	w.button.Disable()
	w.remove.Disable()
}

func bytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
}

func (w *Window) apply(snapshot desktop.Snapshot) {
	w.running = snapshot.Running
	w.items = snapshot.VPNs
	if len(w.items) == 0 {
		w.panel.Hide()
		w.empty.Show()
		w.selected = ""
	} else {
		w.panel.Show()
		w.empty.Hide()
		found := false
		for _, v := range w.items {
			if v.ID == w.selected {
				found = true
			}
		}
		if !found {
			w.selected = w.items[0].ID
		}
	}
	w.list.Refresh()
	for i, v := range w.items {
		if v.ID == w.selected {
			w.list.Select(i)
			break
		}
	}
	if snapshot.Running {
		w.service.Hide()
		w.footer.SetText("Service running · VPNs stay connected when this window closes")
	} else {
		w.service.Show()
		w.footer.SetText("The local service is stopped")
	}
	w.updateDetail()
}

func (w *Window) Refresh() {
	go func() {
		if !w.mu.TryLock() {
			return
		}
		defer w.mu.Unlock()
		snapshot, err := w.client.Status(w.ctx)
		if w.ctx.Err() != nil {
			return
		}
		fyne.Do(func() {
			if err != nil {
				w.footer.SetText(err.Error())
				w.button.Disable()
				w.remove.Disable()
				return
			}
			w.apply(snapshot)
		})
	}()
}

func (w *Window) work(action func(context.Context) error) {
	go func() {
		err := action(w.ctx)
		if w.ctx.Err() != nil {
			return
		}
		fyne.Do(func() {
			if err != nil {
				dialog.ShowError(err, w.window)
			}
			w.Refresh()
		})
	}()
}

func (w *Window) toggle() {
	for _, v := range w.items {
		if v.ID != w.selected || w.busy[v.ID] {
			continue
		}
		id, action := v.ID, "up"
		if v.Desired == "up" {
			action = "down"
		}
		w.perform(id, func(ctx context.Context) error { return w.client.Toggle(ctx, id, action) })
		return
	}
}

func (w *Window) removeVPN() {
	if w.confirmation != nil {
		return
	}
	for _, v := range w.items {
		if v.ID != w.selected || w.busy[v.ID] {
			continue
		}
		id := v.ID
		confirmation := dialog.NewConfirm("Remove VPN", fmt.Sprintf("Remove %q from this computer?\n\nThis disconnects this computer and removes its VPN access. Other devices stay in the VPN. Joining again requires approval.", v.Name), func(confirmed bool) {
			w.confirmation = nil
			if confirmed {
				w.perform(id, func(ctx context.Context) error { return w.client.Remove(ctx, id) })
			}
		}, w.window)
		confirmation.SetConfirmText("Remove")
		confirmation.SetConfirmImportance(widget.DangerImportance)
		w.confirmation = confirmation
		confirmation.Show()
		return
	}
}

func (w *Window) perform(id string, action func(context.Context) error) {
	if w.busy[id] {
		return
	}
	found := false
	for _, v := range w.items {
		if v.ID == id {
			found = true
			break
		}
	}
	if !found {
		return
	}
	w.busy[id] = true
	w.updateDetail()
	go func() {
		err := action(w.ctx)
		if w.ctx.Err() != nil {
			return
		}
		fyne.Do(func() {
			delete(w.busy, id)
			w.updateDetail()
			if err != nil {
				dialog.ShowError(err, w.window)
			}
			w.Refresh()
		})
	}()
}

func (w *Window) ShowAndRun() {
	w.Refresh()
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-w.ctx.Done():
				return
			case <-ticker.C:
				w.Refresh()
			}
		}
	}()
	w.window.ShowAndRun()
}

func (w *Window) Close() { w.window.Close() }

func (w *Window) Canvas() fyne.Canvas { return w.window.Canvas() }
