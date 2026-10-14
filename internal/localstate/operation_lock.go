// SPDX-License-Identifier: GPL-3.0-or-later

package localstate

import (
	"errors"
	"os"
)

func OperationLock(path string) (func(), error) {
	return CLILock(path, true)
}

// Shared CLI locks allow a pending device login and interactive approval to
// coexist. Install/update/uninstall require exclusive access, so no credential
// can be created or changed between upgrade validation and service activation.
func CLILock(path string, exclusive bool) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if exclusive {
		err = tryLockFile(f)
	} else {
		err = tryReadLockFile(f)
	}
	if err != nil {
		f.Close()
		return nil, errors.New("another CLI or installation operation is running; retry after it finishes")
	}
	return func() { unlockFile(f); f.Close() }, nil
}
