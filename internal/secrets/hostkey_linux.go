package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const hostKeyFile = "host.key"
const hostCredentialVersion = "agenttail-host-credential-v1\x00"

// This protects against disclosure of a credential file, not root compromise
// or a full SD-card image: the random host key is root-only on the same device.
// Existing systemd, Keychain and DPAPI stores do not use this backend.
func readHostFile(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0077 != 0 || st.Size > limit {
		return nil, errors.New("host credential files must be root-owned private regular files of the expected size")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("host credential file exceeds size limit")
	}
	return data, err
}

func (s *Store) hostKey(create bool) ([]byte, error) {
	path := filepath.Join(s.Dir, hostKeyFile)
	key, err := readHostFile(path, 32)
	if err == nil {
		if len(key) != 32 {
			clear(key)
			return nil, errors.New("invalid host key; refusing to replace it")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".cred") {
			// Another initial writer may have published the key and its first
			// credential since our initial read. Re-read, never generate over it.
			if existing, e := s.hostKey(false); e == nil {
				return existing, nil
			}
			return nil, errors.New("host key is missing while encrypted credentials exist; restore the original host key")
		}
	}
	key = make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}
	defer clear(key)
	f, err := os.CreateTemp(s.Dir, ".host-key-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(key)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	// Publish a complete key exactly once, even with concurrent first writers.
	if err = os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	dir, err := os.Open(s.Dir)
	if err != nil {
		return nil, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return nil, err
	}
	return s.hostKey(false)
}

func (s *Store) hostCipher(create bool) (cipher.AEAD, error) {
	key, err := s.hostKey(create)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) hostPut(name string, data []byte) error {
	if len(data) > 1024*1024 {
		return errors.New("credential exceeds size limit")
	}
	aead, err := s.hostCipher(true)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := append([]byte(hostCredentialVersion), nonce...)
	sealed = aead.Seal(sealed, nonce, data, []byte(hostCredentialVersion+name))
	defer clear(sealed)
	return atomicWrite(filepath.Join(s.Dir, name+".cred"), sealed)
}

func (s *Store) hostGet(name string) ([]byte, error) {
	data, err := readHostFile(filepath.Join(s.Dir, name+".cred"), 1024*1024+128)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	aead, err := s.hostCipher(false)
	if err != nil {
		return nil, err
	}
	offset := len(hostCredentialVersion)
	if len(data) < offset+aead.NonceSize()+aead.Overhead() || string(data[:offset]) != hostCredentialVersion {
		return nil, errors.New("invalid host credential format")
	}
	return aead.Open(nil, data[offset:offset+aead.NonceSize()], data[offset+aead.NonceSize():], []byte(hostCredentialVersion+name))
}

func (s *Store) hostRemove(name string) error {
	err := os.Remove(filepath.Join(s.Dir, name+".cred"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
