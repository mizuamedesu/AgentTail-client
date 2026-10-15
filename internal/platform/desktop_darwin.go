// SPDX-License-Identifier: GPL-3.0-or-later

package platform

import (
	"os/exec"
	"strconv"
	"strings"
)

func StartDesktopHelper(executable, session, state string) error {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	command := quote(executable) + " --state-dir " + quote(state) + " desktop-helper --session-file " + quote(session) + " </dev/null >/dev/null 2>&1 &"
	return exec.Command("/usr/bin/osascript", "-e", "do shell script "+strconv.Quote(command)+" with administrator privileges").Run()
}
