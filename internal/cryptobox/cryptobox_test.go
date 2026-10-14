// SPDX-License-Identifier: GPL-3.0-or-later

package cryptobox

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vector struct {
	Password             string   `json:"password"`
	Salt                 string   `json:"salt"`
	KDF                  KDF      `json:"kdf"`
	A                    string   `json:"a"`
	E                    string   `json:"e"`
	Owner                string   `json:"owner"`
	ID                   string   `json:"key_id"`
	Private              string   `json:"private"`
	Public               string   `json:"public"`
	Vault                string   `json:"vault"`
	VaultBox             Box      `json:"vault_box"`
	KeyBox               Box      `json:"key_box"`
	RecipientPrivate     string   `json:"recipient_private"`
	RecipientPublic      string   `json:"recipient_public"`
	RecipientFingerprint string   `json:"recipient_fingerprint"`
	Transfer             Transfer `json:"transfer"`
}

func fixturePath() string { return filepath.Join("..", "..", "fixtures", "crypto-v1.json") }

// Explicit maintenance command, never run implicitly by normal tests.
func TestGenerateProtocolVector(t *testing.T) {
	if os.Getenv("UPDATE_CRYPTO_VECTORS") != "1" {
		t.Skip("fixture regeneration not requested")
	}
	v := vector{Password: "twelve words? 日本語と🔐 password", Salt: Encode(bytes.Repeat([]byte{7}, 16)), KDF: DefaultKDF(), Owner: "test-owner", ID: "12345678-1234-4234-8234-123456789abc"}
	d, err := Derive([]byte(v.Password), v.Salt, v.KDF)
	if err != nil {
		t.Fatal(err)
	}
	v.A = d.Auth
	v.E = Encode(d.E)
	private := bytes.Repeat([]byte{11}, 32)
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	v.Private = Encode(private)
	v.Public, err = PublicFromPrivate(private)
	if err != nil {
		t.Fatal(err)
	}
	vault := bytes.Repeat([]byte{23}, 32)
	v.Vault = Encode(vault)
	v.VaultBox, err = seal(d.E, vault, VaultAAD(v.Owner), bytes.Repeat([]byte{2}, 12))
	if err != nil {
		t.Fatal(err)
	}
	v.KeyBox, err = seal(vault, private, KeyAAD(v.Owner, v.ID, v.Public), bytes.Repeat([]byte{3}, 12))
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	v.RecipientPrivate = Encode(recipient.Private.Bytes())
	v.RecipientPublic = recipient.Public
	v.RecipientFingerprint, err = RecipientFingerprint(recipient.Public, "device-test")
	if err != nil {
		t.Fatal(err)
	}
	v.Transfer, err = SealTransfer(recipient.Public, "device-test", v.ID, private, v.RecipientFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath()), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath(), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func readVector(t *testing.T) vector {
	t.Helper()
	data, err := os.ReadFile(fixturePath())
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestProtocolVectorAndDomainSeparation(t *testing.T) {
	v := readVector(t)
	d, err := Derive([]byte(v.Password), v.Salt, v.KDF)
	if err != nil {
		t.Fatal(err)
	}
	if d.Auth != v.A || Encode(d.E) != v.E || d.Auth == Encode(d.E) {
		t.Fatal("KDF protocol mismatch")
	}
	a, _ := Decode(d.Auth, 32)
	if _, err := Open(a, v.VaultBox, VaultAAD(v.Owner)); err == nil {
		t.Fatal("authentication credential opened encryption vault")
	}
	vault, err := Open(d.E, v.VaultBox, VaultAAD(v.Owner))
	if err != nil {
		t.Fatal(err)
	}
	private, err := Open(vault, v.KeyBox, KeyAAD(v.Owner, v.ID, v.Public))
	if err != nil {
		t.Fatal(err)
	}
	if Encode(private) != v.Private {
		t.Fatal("wrong plaintext")
	}
	for _, aad := range []string{KeyAAD("other-owner", v.ID, v.Public), KeyAAD(v.Owner, "other-key", v.Public), KeyAAD(v.Owner, v.ID, "other-public-key")} {
		if _, err := Open(vault, v.KeyBox, aad); err == nil {
			t.Fatal("cross-boundary ciphertext accepted")
		}
	}
	changed := v.KeyBox
	raw, _ := encoding.DecodeString(changed.Ciphertext)
	raw[0] ^= 1
	changed.Ciphertext = Encode(raw)
	if _, err := Open(vault, changed, KeyAAD(v.Owner, v.ID, v.Public)); err == nil {
		t.Fatal("modified ciphertext accepted")
	}
}

func TestEphemeralTransferBoundToDeviceAndKey(t *testing.T) {
	v := readVector(t)
	raw, _ := Decode(v.RecipientPrivate, 32)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := Ephemeral{Private: priv, Public: v.RecipientPublic}
	plain, err := OpenTransfer(r, "device-test", v.ID, v.Transfer)
	if err != nil {
		t.Fatal(err)
	}
	if Encode(plain) != v.Private {
		t.Fatal("wrong transfer plaintext")
	}
	for _, params := range [][2]string{{"other-device", v.ID}, {"device-test", "other-key"}} {
		if _, err := OpenTransfer(r, params[0], params[1], v.Transfer); err == nil {
			t.Fatal("transfer accepted across boundary")
		}
	}
	other, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTransfer(other, "device-test", v.ID, v.Transfer); err == nil {
		t.Fatal("other CLI decrypted transfer")
	}
}

func TestRecipientVerificationRejectsServerKeySubstitution(t *testing.T) {
	v := readVector(t)
	fingerprint, err := RecipientFingerprint(v.RecipientPublic, "device-test")
	if err != nil || fingerprint != v.RecipientFingerprint {
		t.Fatal("recipient fingerprint does not match the shared protocol vector", err)
	}
	private, _ := Decode(v.Private, 32)
	attacker, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ recipient, device, expected string }{
		{attacker.Public, "device-test", fingerprint},
		{v.RecipientPublic, "another-request", fingerprint},
		{v.RecipientPublic, "device-test", ""},
		{v.RecipientPublic, "device-test", "SHA256:invalid"},
		{v.RecipientPublic, "device-test", "SHA256:" + v.Public},
	} {
		box, err := SealTransfer(test.recipient, test.device, v.ID, private, test.expected)
		if err == nil || box.Ciphertext != "" || box.SenderPublic != "" {
			t.Fatal("unverified recipient received an encrypted transfer")
		}
	}
	transfer, err := SealTransfer(v.RecipientPublic, "device-test", v.ID, private, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := Decode(v.RecipientPrivate, 32)
	recipient, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenTransfer(Ephemeral{Private: recipient, Public: v.RecipientPublic}, "device-test", v.ID, transfer)
	if err != nil || !bytes.Equal(plain, private) {
		t.Fatal("verified recipient could not decrypt its key", err)
	}
	if _, err := OpenTransfer(attacker, "device-test", v.ID, transfer); err == nil {
		t.Fatal("substituted recipient could decrypt the legitimate transfer")
	}
}

func TestPasswordChangeRewrapAndRecovery(t *testing.T) {
	v := readVector(t)
	oldE, _ := Decode(v.E, 32)
	vault, err := Open(oldE, v.VaultBox, VaultAAD(v.Owner))
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := Derive([]byte("different strong passphrase"), v.Salt, v.KDF)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := Seal(newKeys.E, vault, VaultAAD(v.Owner))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(oldE, wrap, VaultAAD(v.Owner)); err == nil {
		t.Fatal("old password still opens new wrapping")
	}
	recovered, err := Open(newKeys.E, wrap, VaultAAD(v.Owner))
	if err != nil || !bytes.Equal(recovered, vault) {
		t.Fatal("rewrap lost vault", err)
	}
	recovery, err := RecoveryKey(bytes.Repeat([]byte{9}, 32), v.Owner)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := Seal(recovery, vault, RecoveryAAD(v.Owner))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err = Open(recovery, backup, RecoveryAAD(v.Owner))
	if err != nil || !bytes.Equal(recovered, vault) {
		t.Fatal("recovery failed", err)
	}
	bad := v.KDF
	bad.MemoryKiB = 1 << 30
	if _, err := Derive([]byte(v.Password), v.Salt, bad); err == nil {
		t.Fatal("unbounded server-supplied KDF accepted")
	}
}
