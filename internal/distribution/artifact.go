package distribution

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Verify as bytes are copied, without retaining an executable-sized heap just
// before starting two more processes on a low-memory appliance. The extra byte
// detects oversized responses, including responses without Content-Length.
func copyArtifact(w io.Writer, r io.Reader, a Artifact) error {
	hash := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(w, hash), io.LimitReader(r, a.Size+1), make([]byte, 32*1024))
	if err != nil {
		return err
	}
	if n != a.Size || hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		return errors.New("release artifact SHA-256 or size mismatch")
	}
	return nil
}

// Only publish the complete file after its signed size and hash match. Partial
// downloads and verification failures cannot replace an existing executable.
func writeArtifact(path string, r io.Reader, a Artifact, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".agenttail-artifact-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = copyArtifact(f, r, a); err == nil {
		err = f.Chmod(mode)
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
	return os.Rename(f.Name(), path)
}
