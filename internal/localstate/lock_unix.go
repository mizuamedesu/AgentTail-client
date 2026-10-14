//go:build linux || darwin

package localstate

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func lockBusy(err error) bool { return errors.Is(err, unix.EWOULDBLOCK) }

func lockFile(f *os.File) error        { return unix.Flock(int(f.Fd()), unix.LOCK_EX) }
func unlockFile(f *os.File) error      { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
func tryLockFile(f *os.File) error     { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func tryReadLockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) }
