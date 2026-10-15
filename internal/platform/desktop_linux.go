// SPDX-License-Identifier: GPL-3.0-or-later

package platform

import (
	"errors"
	"os"
	"os/exec"
)

func StartDesktopHelper(executable, session, state string) error {
	if os.Geteuid() == 0 {
		command := exec.Command(executable, "--state-dir", state, "desktop-helper", "--session-file", session)
		if err := command.Start(); err != nil {
			return err
		}
		go func() { _ = command.Wait() }()
		return nil
	}
	path, err := exec.LookPath("pkexec")
	if err != nil {
		return errors.New("polkit (pkexec) is required to authorize VPN management")
	}
	command := exec.Command(path, "--disable-internal-agent", executable, "--state-dir", state, "desktop-helper", "--session-file", session)
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}
