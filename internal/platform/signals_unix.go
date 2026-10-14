// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package platform

import (
	"os"
	"syscall"
)

func Signals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }
