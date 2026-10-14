// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || darwin

package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func privateDirectory(directory string) error {
	if os.Geteuid() != 0 {
		return errors.New("native machine credentials require administrator privileges; run agenttail with sudo")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must not be a symbolic link")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		return errors.New("state directory must be owned by root")
	}
	// A root-owned leaf inside another user's writable directory can be
	// replaced by that user. Validate ancestors, including symlink ownership.
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	for _, parent := range []string{filepath.Dir(filepath.Clean(directory)), filepath.Dir(resolved)} {
		for p := parent; ; p = filepath.Dir(p) {
			i, e := os.Lstat(p)
			if e != nil {
				return e
			}
			st, ok := i.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || i.Mode()&os.ModeSymlink == 0 && i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
				return errors.New("state directory ancestors must be owned by root and protected from replacement")
			}
			if p == "/" {
				break
			}
		}
	}
	return os.Chmod(directory, 0700)
}
