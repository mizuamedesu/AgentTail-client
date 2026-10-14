// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux || windows

package secrets

// Host encryption and machine DPAPI are bound to the protected state scope.
func (s *Store) AuthorizeExecutable(string, []string) error { return nil }
