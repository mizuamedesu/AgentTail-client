// Package cryptobox is client-only. P, its Argon2id output, E, vault keys and
// plaintext WireGuard private keys must never be sent to the account API.
package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/argon2"
)

const FormatVersion = 1

var encoding = base64.RawURLEncoding.Strict()

type KDF struct {
	Algorithm   string `json:"algorithm"`
	Version     int    `json:"version"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

func DefaultKDF() KDF {
	return KDF{Algorithm: "argon2id", Version: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 1}
}
func (k KDF) Validate() error {
	if k != DefaultKDF() {
		return errors.New("unsupported KDF parameters")
	}
	return nil
}

type Derived struct {
	Auth string
	E    []byte
}

func Derive(password []byte, salt string, params KDF) (Derived, error) {
	if err := params.Validate(); err != nil {
		return Derived{}, err
	}
	s, err := decode(salt, 16)
	if err != nil {
		return Derived{}, errors.New("invalid KDF salt")
	}
	if len(password) < 12 || len(password) > 1024 {
		return Derived{}, errors.New("password must contain 12 to 1024 UTF-8 bytes")
	}
	base := argon2.IDKey(password, s, params.Iterations, params.MemoryKiB, params.Parallelism, 32)
	defer clear(base)
	a, err := hkdf.Key(sha256.New, base, s, "agenttail/v1/auth", 32)
	if err != nil {
		return Derived{}, err
	}
	defer clear(a)
	e, err := hkdf.Key(sha256.New, base, s, "agenttail/v1/vault", 32)
	if err != nil {
		return Derived{}, err
	}
	return Derived{Auth: encoding.EncodeToString(a), E: e}, nil
}

type Box struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func Random(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err }
func Salt() (string, error)        { b, err := Random(16); return encoding.EncodeToString(b), err }

func Seal(key, plaintext []byte, aad string) (Box, error) {
	nonce, err := Random(12)
	if err != nil {
		return Box{}, err
	}
	return seal(key, plaintext, aad, nonce)
}
func seal(key, plaintext []byte, aad string, nonce []byte) (Box, error) {
	if len(key) != 32 || len(nonce) != 12 {
		return Box{}, errors.New("invalid AES-256-GCM key or nonce length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Box{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Box{}, err
	}
	return Box{Version: FormatVersion, Nonce: encoding.EncodeToString(nonce), Ciphertext: encoding.EncodeToString(aead.Seal(nil, nonce, plaintext, []byte(aad)))}, nil
}
func Open(key []byte, box Box, aad string) ([]byte, error) {
	if box.Version != FormatVersion || len(key) != 32 {
		return nil, errors.New("unsupported encrypted format or key length")
	}
	nonce, err := decode(box.Nonce, 12)
	if err != nil {
		return nil, err
	}
	data, err := encoding.DecodeString(box.Ciphertext)
	if err != nil || len(data) < 16 || encoding.EncodeToString(data) != box.Ciphertext {
		return nil, errors.New("invalid ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, data, []byte(aad))
	if err != nil {
		return nil, errors.New("encrypted data authentication failed")
	}
	return plain, nil
}

func VaultAAD(owner string) string { return "agenttail/v1/vault/" + owner }
func KeyAAD(owner, id, public string) string {
	return "agenttail/v1/key/" + owner + "/" + id + "/" + public
}
func RecoveryKey(raw []byte, owner string) ([]byte, error) {
	if len(raw) != 32 {
		return nil, errors.New("recovery key must be 32 random bytes")
	}
	return hkdf.Key(sha256.New, raw, nil, "agenttail/v1/recovery/"+owner, 32)
}
func RecoveryAAD(owner string) string { return "agenttail/v1/recovery/" + owner }

type WireGuardKey struct {
	Private []byte
	Public  string
}

func GenerateWireGuard() (WireGuardKey, error) {
	private, err := Random(32)
	if err != nil {
		return WireGuardKey{}, err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := PublicFromPrivate(private)
	if err != nil {
		clear(private)
		return WireGuardKey{}, err
	}
	return WireGuardKey{Private: private, Public: public}, nil
}
func PublicFromPrivate(private []byte) (string, error) {
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return "", errors.New("invalid WireGuard private key")
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func Fingerprint(public string) (string, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(public)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != public {
		return "", errors.New("invalid public key")
	}
	s := sha256.Sum256(b)
	return "SHA256:" + encoding.EncodeToString(s[:]), nil
}

type Ephemeral struct {
	Private *ecdh.PrivateKey
	Public  string
}

func NewEphemeral() (Ephemeral, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Ephemeral{}, err
	}
	return Ephemeral{Private: k, Public: encoding.EncodeToString(k.PublicKey().Bytes())}, nil
}

type Transfer struct {
	Box
	SenderPublic string `json:"sender_public"`
}

var transferRequestID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// RecipientFingerprint is copied from the requesting CLI, independently of the
// account API. Bind it to the request as well as the CLI's own public key.
func RecipientFingerprint(recipientPublic, deviceID string) (string, error) {
	if !transferRequestID.MatchString(deviceID) {
		return "", errors.New("invalid transfer request ID")
	}
	if _, err := decode(recipientPublic, 32); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte("agenttail/v1/device-recipient/" + deviceID + "/" + recipientPublic))
	return "SHA256:" + Encode(sum[:]), nil
}

func VerifyRecipientFingerprint(recipientPublic, deviceID, expected string) error {
	actual, err := RecipientFingerprint(recipientPublic, deviceID)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("recipient fingerprint does not match the requesting CLI")
	}
	return nil
}

func transferAAD(deviceID, keyID, recipient string) string {
	return "agenttail/v1/device/" + deviceID + "/" + keyID + "/" + recipient
}

func SealTransfer(recipientPublic, deviceID, keyID string, plaintext []byte, expectedFingerprint string) (Transfer, error) {
	if err := VerifyRecipientFingerprint(recipientPublic, deviceID, expectedFingerprint); err != nil {
		return Transfer{}, err
	}
	ephemeral, err := NewEphemeral()
	if err != nil {
		return Transfer{}, err
	}
	peerRaw, err := decode(recipientPublic, 32)
	if err != nil {
		return Transfer{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerRaw)
	if err != nil {
		return Transfer{}, err
	}
	shared, err := ephemeral.Private.ECDH(peer)
	if err != nil {
		return Transfer{}, errors.New("invalid ephemeral recipient key")
	}
	defer clear(shared)
	aad := transferAAD(deviceID, keyID, recipientPublic)
	kek, err := hkdf.Key(sha256.New, shared, nil, aad, 32)
	if err != nil {
		return Transfer{}, err
	}
	defer clear(kek)
	box, err := Seal(kek, plaintext, aad)
	return Transfer{Box: box, SenderPublic: ephemeral.Public}, err
}

func OpenTransfer(recipient Ephemeral, deviceID, keyID string, transfer Transfer) ([]byte, error) {
	if recipient.Private == nil {
		return nil, errors.New("missing ephemeral private key")
	}
	peerRaw, err := decode(transfer.SenderPublic, 32)
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerRaw)
	if err != nil {
		return nil, err
	}
	shared, err := recipient.Private.ECDH(peer)
	if err != nil {
		return nil, errors.New("invalid ephemeral sender key")
	}
	defer clear(shared)
	aad := transferAAD(deviceID, keyID, recipient.Public)
	kek, err := hkdf.Key(sha256.New, shared, nil, aad, 32)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	return Open(kek, transfer.Box, aad)
}

func decode(s string, length int) ([]byte, error) {
	b, err := encoding.DecodeString(s)
	if err != nil || len(b) != length || encoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("expected %d-byte base64url value", length)
	}
	return b, nil
}

// Encode/Decode encode only explicit public/encrypted fields at call sites.
func Encode(b []byte) string                      { return encoding.EncodeToString(b) }
func Decode(s string, length int) ([]byte, error) { return decode(s, length) }
func Hex(b []byte) string                         { return hex.EncodeToString(b) }
