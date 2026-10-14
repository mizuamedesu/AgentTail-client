// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux

package secrets

// The native provider's machine-wide wrapping keys belong to the OS.
func (s *Store) Purge() error { return nil }
