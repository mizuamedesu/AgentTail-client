// SPDX-License-Identifier: GPL-3.0-or-later

//go:build desktop

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/mizuamedesu/AgentTail-client/internal/desktop"
	"github.com/mizuamedesu/AgentTail-client/internal/desktopui"
)

var version = "dev"

//go:embed icon.svg
var icon []byte

func main() {
	showVersion := flag.Bool("version", false, "show the desktop version")
	flag.Bool("json", false, "print version as JSON")
	flag.Parse()
	if *showVersion {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "data": map[string]string{"version": version, "component": "desktop"}})
		return
	}
	application := app.NewWithID("io.agenttail.desktop")
	application.SetIcon(fyne.NewStaticResource("agenttail.svg", icon))
	if acceptanceWindow(application) {
		return
	}
	client, cleanup, err := desktop.Launch(context.Background(), version)
	if err != nil {
		window := application.NewWindow("AgentTail")
		message := widget.NewLabel(err.Error())
		message.Wrapping = fyne.TextWrapWord
		window.SetContent(container.NewPadded(container.NewVBox(widget.NewLabelWithStyle("Unable to open VPN manager", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), message, widget.NewButton("Close", window.Close))))
		window.Resize(fyne.NewSize(480, 180))
		window.ShowAndRun()
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer cleanup()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		client.Close(ctx)
	}()
	desktopui.New(application, client).ShowAndRun()
}
