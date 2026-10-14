// SPDX-License-Identifier: GPL-3.0-or-later

package secrets

// NanoKVM's Buildroot image has no systemd credential service. Keep persistent
// state under /etc: /var is volatile on some appliance images.
func DefaultDirectory() string                      { return "/etc/agenttail" }
func (s *Store) put(name string, data []byte) error { return s.hostPut(name, data) }
func (s *Store) get(name string) ([]byte, error)    { return s.hostGet(name) }
func (s *Store) remove(name string) error           { return s.hostRemove(name) }
