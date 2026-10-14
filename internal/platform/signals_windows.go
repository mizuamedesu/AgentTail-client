// SPDX-License-Identifier: GPL-3.0-or-later

package platform

import "os"

func Signals() []os.Signal { return []os.Signal{os.Interrupt} }
