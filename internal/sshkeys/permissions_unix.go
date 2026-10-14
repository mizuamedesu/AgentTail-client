// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package sshkeys

import (
	"errors"
	"os"
	"syscall"
)

func owned(i os.FileInfo) error {
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) || i.Mode().Perm()&0022 != 0 || !i.IsDir() && s.Nlink != 1 {
		return errors.New("SSH files must belong to the current user, have no other hard links, and not be writable by others")
	}
	return nil
}
func protect(path string, directory bool) error {
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
func lock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

func InstallPublicCurrent(home, public string) (string, error) { return InstallPublic(home, public) }
