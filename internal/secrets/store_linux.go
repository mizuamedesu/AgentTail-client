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
func (s *Store) run(operation, credential string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := []string{operation, "--name=" + credential}
	if operation == "encrypt" {
		args = append(args, "--with-key=host")
	}
	args = append(args, "-", "-")
	command := exec.CommandContext(ctx, "/usr/bin/systemd-creds", args...)
	command.Stdin = bytes.NewReader(input)
	data, err := command.Output()
	if err != nil {
		clear(data)
		return nil, errors.New("systemd credential operation failed; systemd-creds 250+ and root access are required")
	}
	return data, nil
}
func (s *Store) put(credential string, data []byte) error {
	ciphertext, err := s.run("encrypt", credential, data)
	if err != nil {
		return err
	}
	defer clear(ciphertext)
	return atomicWrite(filepath.Join(s.Dir, credential+".cred"), ciphertext)
}
func (s *Store) get(credential string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, credential+".cred"))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return s.run("decrypt", credential, data)
}
func (s *Store) remove(credential string) error {
	err := os.Remove(filepath.Join(s.Dir, credential+".cred"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
