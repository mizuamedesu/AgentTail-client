package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func (s *Store) Purge() error {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".cred") {
			return errors.New("encrypted credentials remain; host key retained")
		}
	}
	err = os.Remove(filepath.Join(s.Dir, hostKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
