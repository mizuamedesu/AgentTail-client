package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPurgePreservesLiveCredentials(t *testing.T) {
	s := hostStore(t)
	if err := s.Put("key/test", "public fixture"); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(); err == nil {
		t.Fatal("host key deleted with live credentials")
	}
	if err := s.Delete("key/test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, hostKeyFile)); !os.IsNotExist(err) {
		t.Fatal("host key remains after purge")
	}
}
