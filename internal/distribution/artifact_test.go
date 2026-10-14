package distribution

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactStreamRejectsInvalidDataWithoutReplacingFile(t *testing.T) {
	data := "signed executable fixture"
	sum := sha256.Sum256([]byte(data))
	a := Artifact{Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sum)}
	for name, input := range map[string]string{"valid": data, "truncated": data[:5], "oversized": data + "x", "tampered": strings.Repeat("x", len(data))} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "executable")
			if err := os.WriteFile(path, []byte("previous"), 0600); err != nil {
				t.Fatal(err)
			}
			err := writeArtifact(path, strings.NewReader(input), a, 0755)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid executable published")
			}
			want := "previous"
			if name == "valid" {
				want = data
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != want {
				t.Fatal("destination changed on failed verification", string(got), err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatal("partial files retained", entries, err)
			}
		})
	}
}

type zeroArtifact struct{ read, maxRead int64 }

func (r *zeroArtifact) Read(p []byte) (int, error) {
	r.read += int64(len(p))
	if int64(len(p)) > r.maxRead {
		r.maxRead = int64(len(p))
	}
	clear(p)
	return len(p), nil
}

func TestArtifactStreamBoundsLargeResponses(t *testing.T) {
	const size = 10 * 1024 * 1024
	r := &zeroArtifact{}
	if err := copyArtifact(io.Discard, r, Artifact{Size: size}); err == nil {
		t.Fatal("oversized response accepted")
	}
	if r.read != size+1 || r.maxRead > 32*1024 {
		t.Fatalf("unbounded artifact buffering: bytes=%d max_read=%d", r.read, r.maxRead)
	}
}

func BenchmarkArtifactCopy(b *testing.B) {
	const size = 10 * 1024 * 1024
	hash := sha256.New()
	io.Copy(hash, io.LimitReader(&zeroArtifact{}, size))
	a := Artifact{Size: size, SHA256: fmt.Sprintf("%x", hash.Sum(nil))}
	b.ReportAllocs()
	b.SetBytes(size)
	b.ResetTimer()
	for range b.N {
		if err := copyArtifact(io.Discard, io.LimitReader(&zeroArtifact{}, size), a); err != nil {
			b.Fatal(err)
		}
	}
}
