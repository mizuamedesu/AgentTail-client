// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package desktop

import (
	"os/exec"
	"runtime"
)

func InstalledCLI(version string) (string, error) {
	if runtime.GOOS == "darwin" {
		return "/Library/AgentTail/agenttail", nil
	}
	return "/usr/local/lib/agenttail/agenttail", nil
}

func OpenWindow() error {
	var command *exec.Cmd
	if runtime.GOOS == "darwin" {
		command = exec.Command("/usr/bin/open", "/Applications/AgentTail.app")
	} else {
		path, err := windowExecutable("/usr/local/lib/agenttail")
		if err != nil {
			return err
		}
		command = exec.Command(path)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}

func installedRoot() (string, error) {
	if runtime.GOOS == "darwin" {
		return "/Library/AgentTail", nil
	}
	return "/usr/local/lib/agenttail", nil
}
