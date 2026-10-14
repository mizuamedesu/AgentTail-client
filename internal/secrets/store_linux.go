// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux && !riscv64

package secrets

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func DefaultDirectory() string { return "/var/lib/agenttail" }
func systemdCredentialsCommand() string {
	for _, path := range []string{"/usr/bin/systemd-creds", "/bin/systemd-creds"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path
		}
	}
	return ""
}

func (s *Store) run(commandPath, operation, credential string, input []byte) ([]byte, error) {
	if commandPath == "" {
		return nil, errors.New("this credential uses systemd encryption; restore systemd-creds 250+ to read or update it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := []string{operation, "--name=" + credential}
	if operation == "encrypt" {
		args = append(args, "--with-key=host")
	}
	args = append(args, "-", "-")
	command := exec.CommandContext(ctx, commandPath, args...)
	command.Stdin = bytes.NewReader(input)
	data, err := command.Output()
	if err != nil {
		clear(data)
		return nil, errors.New("systemd credential operation failed; systemd-creds 250+ and root access are required")
	}
	return data, nil
}
func (s *Store) put(credential string, data []byte) error {
	return s.linuxPut(credential, data, systemdCredentialsCommand())
}

// Preserve each credential's provider across changes to the installed tools.
// An unreadable systemd ciphertext must never be replaced with a new host key.
func (s *Store) linuxPut(credential string, data []byte, command string) error {
	existing, err := readHostFile(filepath.Join(s.Dir, credential+".cred"), 2*1024*1024)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	isHost := bytes.HasPrefix(existing, []byte(hostCredentialVersion))
	hasExisting := err == nil
	clear(existing)
	if isHost || command == "" && !hasExisting {
		return s.hostPut(credential, data)
	}
	ciphertext, err := s.run(command, "encrypt", credential, data)
	if err != nil {
		return err
	}
	defer clear(ciphertext)
	return atomicWrite(filepath.Join(s.Dir, credential+".cred"), ciphertext)
}
func (s *Store) get(credential string) ([]byte, error) {
	data, err := readHostFile(filepath.Join(s.Dir, credential+".cred"), 2*1024*1024)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if bytes.HasPrefix(data, []byte(hostCredentialVersion)) {
		return s.hostGet(credential)
	}
	return s.run(systemdCredentialsCommand(), "decrypt", credential, data)
}
func (s *Store) remove(credential string) error {
	err := os.Remove(filepath.Join(s.Dir, credential+".cred"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
