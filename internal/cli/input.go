// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"golang.org/x/term"
	"os"
	"strings"
)

func prompt(label string, secret bool) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("interactive terminal required; passwords cannot be supplied in flags, environment variables or redirected stdin")
	}
	fmt.Fprint(os.Stderr, label+": ")
	if secret {
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		defer clear(value)
		return string(value), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line), err
}
func publicFingerprint(public string) (string, error) { return cryptobox.Fingerprint(public) }
func newPassword() (string, error) {
	p, err := prompt("New password (12+ UTF-8 bytes)", true)
	if err != nil {
		return "", err
	}
	repeat, err := prompt("Confirm new password", true)
	if err != nil {
		return "", err
	}
	if p != repeat {
		return "", errors.New("passwords do not match")
	}
	return p, nil
}
