package distribution

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestReleaseVerificationRejectsUntrustedMetadata(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	valid := fmt.Sprintf("agenttail-manifest-v1\nversion 1.2.3\nsequence 7\ncreated %d\nexpires %d\nfile linux amd64 vpn vpn-linux-amd64 3 %s -\n", now.Unix(), now.Add(time.Hour).Unix(), strings.Repeat("a", 64))
	check := func(raw string) (Manifest, error) {
		hash := sha256.Sum256([]byte(raw))
		sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if e != nil {
			t.Fatal(e)
		}
		return verify([]byte(raw), sig, &key.PublicKey, now)
	}
	m, err := check(valid)
	if err != nil || m.Sequence != 7 {
		t.Fatal(m, err)
	}
	if _, err = m.Platform("windows", "amd64"); err == nil {
		t.Fatal("incomplete Windows release accepted")
	}
	riscv, err := check(strings.ReplaceAll(valid, "amd64", "riscv64"))
	if err != nil {
		t.Fatal("NanoKVM manifest rejected", err)
	}
	if _, err = riscv.Platform("linux", "riscv64"); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"non-Linux RISC-V":   strings.ReplaceAll(strings.ReplaceAll(valid, "amd64", "riscv64"), "linux", "windows"),
		"path traversal":     strings.Replace(valid, "vpn-linux-amd64", "../../vpn", 1),
		"negative size":      strings.Replace(valid, " 3 ", " -1 ", 1),
		"oversize":           strings.Replace(valid, " 3 ", " 999999999 ", 1),
		"duplicate sequence": valid + "sequence 8\n",
		"unknown command":    valid + "exec whoami\n",
		"expired":            strings.Replace(valid, fmt.Sprint(now.Add(time.Hour).Unix()), fmt.Sprint(now.Add(-time.Second).Unix()), 1),
		"future":             strings.Replace(valid, fmt.Sprintf("created %d", now.Unix()), fmt.Sprintf("created %d", now.Add(time.Hour).Unix()), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := check(raw); err == nil {
				t.Fatal("unsafe signed manifest accepted")
			}
		})
	}
	hash := sha256.Sum256([]byte(valid))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if _, err = verify([]byte(valid+"\n"), sig, &key.PublicKey, now); err == nil {
		t.Fatal("tampering accepted")
	}
	wrong, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verify([]byte(valid), sig, &wrong.PublicKey, now); err == nil {
		t.Fatal("untrusted key accepted")
	}
}

func TestArtifactAndStageBoundary(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("isolated Unix root filesystem checks")
	}
	data := []byte("verified executable bytes")
	hash := sha256.Sum256(data)
	a := Artifact{OS: runtime.GOOS, Arch: runtime.GOARCH, Role: "vpn", Name: "native", Size: int64(len(data)), SHA256: fmt.Sprintf("%x", hash)}
	if checkArtifact(append(data, 'x'), a) == nil {
		t.Fatal("extra artifact bytes accepted")
	}
	bundle := t.TempDir()
	os.WriteFile(filepath.Join(bundle, "native"), data, 0600)
	b, err := os.OpenRoot(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	root := t.TempDir()
	m := &Manager{Root: root, Launcher: filepath.Join(root, "bin", "agenttail")}
	r := &Record{Version: "1.2.3", Digest: strings.Repeat("a", 64), ReleaseID: "1.2.3-" + strings.Repeat("a", 16)}
	manifest := Manifest{Files: []Artifact{a}, Raw: []byte("verified manifest fixture"), Signature: []byte("signature fixture")}
	if err = m.stage(manifest, b, r); err != nil {
		t.Fatal(err)
	}
	if err = m.activate(r); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(m.Launcher)
	if err != nil || string(got) != string(data) {
		t.Fatal("activation did not select verified bytes", err)
	}
	legacy := filepath.Join(root, "vpn")
	if err = os.Symlink(m.executable(r), legacy); err != nil {
		t.Fatal(err)
	}
	if err = m.removeLegacyLauncher(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatal("managed legacy launcher was not removed", err)
	}
	if err = os.WriteFile(legacy, []byte("other product"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = m.removeLegacyLauncher(); err != nil {
		t.Fatal(err)
	}
	if got, err = os.ReadFile(legacy); err != nil || string(got) != "other product" {
		t.Fatal("unrelated vpn command was changed", err)
	}
	// A later retry cannot silently reuse a tampered staged executable.
	os.WriteFile(m.executable(r), []byte("tampered"), 0755)
	if err = m.stage(manifest, b, r); err == nil {
		t.Fatal("tampered staged release reused")
	}
	if err = m.removeLauncher(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(m.Launcher, []byte("unrelated vpn program"), 0755)
	if err = m.activate(r); err == nil {
		t.Fatal("unrelated vpn command overwritten")
	}
}

func TestDownloadSourceHasNoCredentialOrRedirectChannel(t *testing.T) {
	for _, source := range []string{"http://example.test", "https://user:secret@example.test/", "https://example.test/?token=secret", "https://example.test/#x", "file:///tmp/a"} {
		if ValidateSource(source) == nil {
			t.Fatal("unsafe source accepted", source)
		}
	}
	if err := ValidateSource("https://example.test/releases/stable"); err != nil {
		t.Fatal(err)
	}
}
