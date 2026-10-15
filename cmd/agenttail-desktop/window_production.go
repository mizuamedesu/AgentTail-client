// SPDX-License-Identifier: GPL-3.0-or-later

//go:build desktop && !acceptance

package main

import "fyne.io/fyne/v2"

func acceptanceWindow(fyne.App) bool { return false }
