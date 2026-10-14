// SPDX-License-Identifier: GPL-3.0-or-later

package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
)

func TestNativeSecretRoundTripAndScope(t *testing.T) {
	if os.Getenv("AGENTTAIL_TEST_NATIVE_SECRETS") != "1" {
		t.Skip("explicit opt-in required to exercise the real OS secret store")
	}
	directory, err := os.MkdirTemp("", "agenttail-secret-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	store, err := New(directory)
	if err != nil {
		t.Fatal(err)
	}
	scope := "public-test/" + uuid.NewString()
	defer store.Delete(scope)
	want := map[string]string{"private_key": "public-test-secret-never-use-as-a-real-key"}
	if err = store.Put(scope, want); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err = store.Get(scope, &got); err != nil {
		t.Fatal(err)
	}
	if got["private_key"] != want["private_key"] {
		t.Fatal("native roundtrip changed secret")
	}
	if err = store.Get(scope+"-other", &got); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong scope accessible: %v", err)
	}
	if runtime.GOOS != "darwin" {
		files, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		credentials := files[:0]
		for _, file := range files {
			if runtime.GOOS == "linux" && file.Name() == "host.key" {
				continue
			}
			credentials = append(credentials, file)
		}
		if len(credentials) != 1 {
			t.Fatal("unexpected credential files")
		}
		data, err := os.ReadFile(filepath.Join(directory, credentials[0].Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(want["private_key"])) {
			t.Fatal("plaintext secret persisted")
		}
	}
	if err = store.Delete(scope); err != nil {
		t.Fatal(err)
	}
	if err = store.Get(scope, &got); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted secret remains readable")
	}
}
