package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func hostStore(t *testing.T) *Store {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned host credential fixtures require root")
	}
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestHostKeyRoundTripTamperAndScope(t *testing.T) {
	s := hostStore(t)
	name := s.name("key/public-fixture")
	secret := []byte("public-test-key-never-use-for-real-credentials")
	if err := s.hostPut(name, secret); err != nil {
		t.Fatal(err)
	}
	got, err := s.hostGet(name)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("roundtrip: %v", err)
	}
	path := filepath.Join(s.Dir, name+".cred")
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("plaintext persisted")
	}
	other := s.name("session/account")
	if err = os.WriteFile(filepath.Join(s.Dir, other+".cred"), sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.hostGet(other); err == nil {
		t.Fatal("scope substitution accepted")
	}
	sealed[len(sealed)-1] ^= 1
	if err = os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.hostGet(name); err == nil {
		t.Fatal("tampered credential accepted")
	}
	if err = s.hostRemove(name); err != nil {
		t.Fatal(err)
	}
	if _, err = s.hostGet(name); !os.IsNotExist(err) {
		t.Fatal("deleted credential remains")
	}
}
func TestHostKeyMissingCorruptAndPermissions(t *testing.T) {
	for _, failure := range []string{"missing", "truncated", "permissions", "symlink"} {
		t.Run(failure, func(t *testing.T) {
			s := hostStore(t)
			name := s.name("key/test")
			if err := s.hostPut(name, []byte("fixture")); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(s.Dir, hostKeyFile)
			var err error
			switch failure {
			case "missing":
				err = os.Remove(key)
			case "truncated":
				err = os.WriteFile(key, []byte("bad"), 0600)
			case "permissions":
				err = os.Chmod(key, 0644)
			case "symlink":
				err = os.Rename(key, key+".saved")
				if err == nil {
					err = os.Symlink(key+".saved", key)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.hostGet(name); err == nil {
				t.Fatal("insecure or lost key accepted")
			}
			if err = s.hostPut(name, []byte("replacement")); err == nil {
				t.Fatal("existing key silently replaced")
			}
		})
	}
}
func TestHostKeyConcurrentCreationAndRestart(t *testing.T) {
	s := hostStore(t)
	var wg sync.WaitGroup
	for _, scope := range []string{"key/one", "key/two", "session/account", "session/admin"} {
		wg.Add(1)
		go func(scope string) {
			defer wg.Done()
			if err := s.hostPut(s.name(scope), []byte(scope)); err != nil {
				t.Error(err)
			}
		}(scope)
	}
	wg.Wait()
	reopened, err := New(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"key/one", "key/two", "session/account", "session/admin"} {
		got, err := reopened.hostGet(reopened.name(scope))
		if err != nil || string(got) != scope {
			t.Fatalf("after restart: %v", err)
		}
	}
}
