// Package secrets stores client credentials using the native OS secret facility.
// Key credentials and account/admin sessions occupy distinct named entries.
package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Store struct{ Dir string }

func New(directory string) (*Store, error) {
	if directory == "" {
		directory = DefaultDirectory()
	}
	if !filepath.IsAbs(directory) {
		return nil, errors.New("state directory must be absolute")
	}
	if err := privateDirectory(directory); err != nil {
		return nil, err
	}
	return &Store{Dir: directory}, nil
}
func (s *Store) name(scope string) string {
	directory := filepath.Clean(s.Dir)
	if runtime.GOOS == "windows" {
		directory = strings.ToLower(directory)
	}
	sum := sha256.Sum256([]byte("agenttail/v1/secret/" + directory + "/" + scope))
	return "agenttail-" + hex.EncodeToString(sum[:])
}
func (s *Store) Put(scope string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(data)
	return s.put(s.name(scope), data)
}
func (s *Store) Get(scope string, output any) error {
	data, err := s.get(s.name(scope))
	if err != nil {
		return err
	}
	defer clear(data)
	return json.Unmarshal(data, output)
}
func (s *Store) Delete(scope string) error { return s.remove(s.name(scope)) }

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".agenttail-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
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
	return os.Rename(temporary, path)
}
