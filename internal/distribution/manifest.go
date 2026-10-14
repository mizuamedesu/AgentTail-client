// SPDX-License-Identifier: GPL-3.0-or-later

// Package distribution verifies and installs versioned native releases.
// Flat manifests avoid executing archive paths or extraction hooks.
package distribution

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed trusted.pub
var trustedPEM []byte

const MaxManifest = 64 * 1024
const MaxArtifact = 64 * 1024 * 1024

const SignatureVerification = "signature"
const ChecksumVerification = "https-sha256"

var safeVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?$`)
var safeFile = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Artifact struct {
	OS, Arch, Role, Name, SHA256 string
	Size                         int64
}
type Manifest struct {
	Version          string
	Sequence         uint64
	Created, Expires int64
	Files            []Artifact
	Digest           string
	Raw, Signature   []byte
}

func publicKey(data []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid release trust key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 3072 {
		return nil, errors.New("release trust key must be RSA 3072 or stronger")
	}
	return pub, nil
}

func Verify(raw, signature []byte, now time.Time) (Manifest, error) {
	key, err := publicKey(trustedPEM)
	if err != nil {
		return Manifest{}, err
	}
	return verify(raw, signature, key, now)
}

func verify(raw, signature []byte, key *rsa.PublicKey, now time.Time) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifest {
		return Manifest{}, errors.New("release manifest size is invalid")
	}
	hash := sha256.Sum256(raw)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature); err != nil {
		return Manifest{}, errors.New("release signature verification failed")
	}
	return parseManifest(raw, signature, now)
}

// VerifyChecksum checks a manifest against the hash obtained from its HTTPS
// release source. Publisher authentication is provided by HTTPS in this mode.
// It is selected explicitly and is never a fallback for an invalid signature.
func VerifyChecksum(raw, checksum []byte, now time.Time) (Manifest, error) {
	hash := sha256.Sum256(raw)
	expected := fmt.Sprintf("%x  manifest.txt\n", hash)
	if string(checksum) != expected {
		return Manifest{}, errors.New("release manifest SHA-256 mismatch")
	}
	return parseManifest(raw, checksum, now)
}

func verificationMethod(method string) (string, error) {
	if method == "" {
		return SignatureVerification, nil // Existing installation records.
	}
	if method != SignatureVerification && method != ChecksumVerification {
		return "", errors.New("unsupported release verification method")
	}
	return method, nil
}

func verifyRelease(raw, proof []byte, method string, now time.Time) (Manifest, error) {
	method, err := verificationMethod(method)
	if err != nil {
		return Manifest{}, err
	}
	if method == ChecksumVerification {
		return VerifyChecksum(raw, proof, now)
	}
	return Verify(raw, proof, now)
}

func proofFile(method string) string {
	if method == ChecksumVerification {
		return "manifest.sha256"
	}
	return "manifest.sig"
}

func parseManifest(raw, proof []byte, now time.Time) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > MaxManifest {
		return m, errors.New("release manifest size is invalid")
	}
	hash := sha256.Sum256(raw)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	if !scanner.Scan() || scanner.Text() != "agenttail-manifest-v1" {
		return m, errors.New("unsupported release manifest")
	}
	seen := map[string]bool{}
	files := map[string]bool{}
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 0 {
			return m, errors.New("empty manifest record")
		}
		kind := parts[0]
		if kind != "file" {
			if len(parts) != 2 || seen[kind] {
				return m, errors.New("duplicate or malformed manifest record")
			}
			seen[kind] = true
		}
		var err error
		switch kind {
		case "version":
			m.Version = parts[1]
		case "sequence":
			m.Sequence, err = strconv.ParseUint(parts[1], 10, 64)
		case "created":
			m.Created, err = strconv.ParseInt(parts[1], 10, 64)
		case "expires":
			m.Expires, err = strconv.ParseInt(parts[1], 10, 64)
		case "file":
			if len(parts) != 8 {
				return m, errors.New("malformed artifact record")
			}
			f := Artifact{OS: parts[1], Arch: parts[2], Role: parts[3], Name: parts[4], SHA256: parts[6]}
			f.Size, err = strconv.ParseInt(parts[5], 10, 64)
			if parts[7] != "-" || !safeFile.MatchString(f.Name) || !digestPattern.MatchString(f.SHA256) || f.Size < 1 || f.Size > MaxArtifact {
				return m, errors.New("invalid artifact path, digest or size")
			}
			if f.OS != "linux" && f.OS != "darwin" && f.OS != "windows" || (f.Arch != "amd64" && f.Arch != "arm64" && !(f.OS == "linux" && f.Arch == "riscv64")) || f.Role != "vpn" && f.Role != "wintun" && f.Role != "license" {
				return m, errors.New("unsupported artifact platform or role")
			}
			id := f.OS + "/" + f.Arch + "/" + f.Role
			if seen[id] || files[f.Name] {
				return m, errors.New("duplicate artifact")
			}
			seen[id], files[f.Name] = true, true
			m.Files = append(m.Files, f)
		default:
			return m, fmt.Errorf("unknown manifest record %q", kind)
		}
		if err != nil {
			return m, errors.New("invalid numeric manifest field")
		}
	}
	if err := scanner.Err(); err != nil {
		return m, err
	}
	if !safeVersion.MatchString(m.Version) || m.Sequence == 0 || m.Created <= 0 || m.Created > now.Unix()+300 || m.Expires <= now.Unix() || m.Expires <= m.Created || m.Expires-m.Created > 366*86400 || len(m.Files) == 0 {
		return m, errors.New("release is expired, future-dated, or has invalid metadata")
	}
	m.Raw, m.Signature, m.Digest = bytes.Clone(raw), bytes.Clone(proof), hex.EncodeToString(hash[:])
	return m, nil
}

func (m Manifest) Platform(goos, arch string) ([]Artifact, error) {
	var result []Artifact
	roles := map[string]bool{}
	for _, f := range m.Files {
		if f.OS == goos && f.Arch == arch {
			result = append(result, f)
			roles[f.Role] = true
		}
	}
	if !roles["vpn"] || goos == "windows" && (!roles["wintun"] || !roles["license"]) {
		return nil, errors.New("release does not contain all required files for this platform")
	}
	return result, nil
}

func installedName(a Artifact) string {
	if a.Role == "wintun" {
		return "wintun.dll"
	}
	if a.Role == "license" {
		return "WINTUN-LICENSE.txt"
	}
	if a.OS == "windows" {
		return "vpn.exe"
	}
	return "vpn"
}
