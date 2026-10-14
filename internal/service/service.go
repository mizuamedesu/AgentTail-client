// SPDX-License-Identifier: GPL-3.0-or-later

// Package service integrates the same agent with the native boot service manager.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Status struct {
	Name        string `json:"name"`
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
	LastFailure string `json:"last_failure,omitempty"`
}

func Validate(executable, directory string) error {
	for _, path := range []string{executable, directory} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
			return errors.New("service paths must be absolute and contain no line breaks")
		}
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("service executable does not exist")
	}
	return nil
}
func run(program string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, program, args...).Run(); err != nil {
		return fmt.Errorf("service manager %s %s failed: %w", program, strings.Join(args, " "), err)
	}
	return nil
}
func write(path string, data []byte) error {
	return writeMode(path, data, 0644)
}

func writeMode(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".agenttail-service-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
