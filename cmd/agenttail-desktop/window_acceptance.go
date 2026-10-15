// SPDX-License-Identifier: GPL-3.0-or-later

//go:build desktop && acceptance

package main

import (
	"flag"
	"fyne.io/fyne/v2"
	"github.com/mizuamedesu/AgentTail-client/internal/desktopui"
	"os"
)

var acceptanceProof = flag.String("acceptance-ui-proof", "", "CI-only native window checks; never distribute this executable")

func acceptanceWindow(application fyne.App) bool {
	if *acceptanceProof == "" {
		return false
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		panic("the GUI acceptance fixture is CI-only")
	}
	desktopui.RunAcceptanceWindow(application, version, *acceptanceProof)
	return true
}
