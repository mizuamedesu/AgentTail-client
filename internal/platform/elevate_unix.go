// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package platform

import (
	"errors"
	"os"
	"os/exec"
)

func Elevate() (bool, int, error) {
	if os.Geteuid() == 0 {
		return false, 0, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, 0, err
	}
	path, err := exec.LookPath("sudo")
	if err != nil {
		return false, 0, errors.New("administrator access is required; run agenttail as root")
	}
	command := exec.Command(path, append([]string{"--", exe}, os.Args[1:]...)...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err = command.Run()
	if err == nil {
		return true, 0, nil
	}
	var status *exec.ExitError
	if errors.As(err, &status) {
		return true, status.ExitCode(), nil
	}
	return false, 0, err
}
