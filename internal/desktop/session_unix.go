// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package desktop

import "os"

func protectSessionDirectory(path string) error { return os.Chmod(path, 0700) }
