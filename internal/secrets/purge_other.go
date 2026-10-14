//go:build !linux || !riscv64

package secrets

// The native provider's machine-wide wrapping keys belong to the OS.
func (s *Store) Purge() error { return nil }
