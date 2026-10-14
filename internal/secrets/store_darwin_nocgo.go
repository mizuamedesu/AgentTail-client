//go:build darwin && !cgo

package secrets

import "errors"

func DefaultDirectory() string { return "/Library/Application Support/AgentTail" }

var errNativeKeychain = errors.New("this macOS build lacks native Keychain support; install the native release built with CGO_ENABLED=1")

func (s *Store) put(string, []byte) error                   { return errNativeKeychain }
func (s *Store) get(string) ([]byte, error)                 { return nil, errNativeKeychain }
func (s *Store) remove(string) error                        { return errNativeKeychain }
func (s *Store) AuthorizeExecutable(string, []string) error { return errNativeKeychain }
