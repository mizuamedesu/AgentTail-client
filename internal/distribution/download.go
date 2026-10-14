// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = errors.New("release response exceeds size limit")
	}
	return b, err
}
func ValidateSource(source string) error {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("release source must be an HTTPS URL without credentials, query or fragment")
	}
	return nil
}

func releaseClient() (*http.Client, *http.Transport) {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport
}

func releaseFile(ctx context.Context, client *http.Client, source, name string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(source, "/")+"/"+name, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("release download failed")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New("release server did not return HTTP 200")
	}
	return resp.Body, nil
}

func releaseMetadata(ctx context.Context, client *http.Client, source string) ([]byte, []byte, error) {
	return releaseMetadataWithVerification(ctx, client, source, SignatureVerification)
}

func releaseMetadataWithVerification(ctx context.Context, client *http.Client, source, method string) ([]byte, []byte, error) {
	if err := ValidateSource(source); err != nil {
		return nil, nil, err
	}
	method, err := verificationMethod(method)
	if err != nil {
		return nil, nil, err
	}
	get := func(name string, limit int64) ([]byte, error) {
		body, err := releaseFile(ctx, client, source, name)
		if err != nil {
			return nil, err
		}
		defer body.Close()
		return readLimited(body, limit)
	}
	raw, err := get("manifest.txt", MaxManifest)
	if err != nil {
		return nil, nil, err
	}
	sig, err := get(proofFile(method), 2048)
	return raw, sig, err
}

// LatestManifest retrieves only public metadata, with the same HTTPS and pinned
// signature verification as an update. It never downloads executable artifacts.
func LatestManifest(ctx context.Context, source string) (Manifest, error) {
	return LatestManifestWithVerification(ctx, source, SignatureVerification)
}

func LatestManifestWithVerification(ctx context.Context, source, method string) (Manifest, error) {
	client, transport := releaseClient()
	defer transport.CloseIdleConnections()
	raw, sig, err := releaseMetadataWithVerification(ctx, client, source, method)
	if err != nil {
		return Manifest{}, err
	}
	return verifyRelease(raw, sig, method, time.Now())
}

// Download uses the legacy signature policy. DownloadWithVerification selects
// an explicit policy; both use HTTPS without account credentials or redirects.
func Download(ctx context.Context, source string) (string, func(), error) {
	return DownloadWithVerification(ctx, source, SignatureVerification)
}

func DownloadWithVerification(ctx context.Context, source, method string) (string, func(), error) {
	method, err := verificationMethod(method)
	if err != nil {
		return "", nil, err
	}
	if err := ValidateSource(source); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "agenttail-release-")
	if err != nil {
		return "", nil, err
	}
	clean := func() { os.RemoveAll(dir) }
	client, transport := releaseClient()
	defer transport.CloseIdleConnections()
	fetch := func(name string) (io.ReadCloser, error) {
		return releaseFile(ctx, client, source, name)
	}
	raw, sig, err := releaseMetadataWithVerification(ctx, client, source, method)
	if err != nil {
		clean()
		return "", nil, err
	}
	m, err := verifyRelease(raw, sig, method, time.Now())
	if err != nil {
		clean()
		return "", nil, err
	}
	files, err := m.Platform(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		clean()
		return "", nil, err
	}
	for _, a := range files {
		body, e := fetch(a.Name)
		if e == nil {
			e = writeArtifact(filepath.Join(dir, a.Name), body, a, 0600)
			body.Close()
		}
		if e != nil {
			clean()
			return "", nil, e
		}
	}
	if err = os.WriteFile(filepath.Join(dir, "manifest.txt"), raw, 0600); err == nil {
		err = os.WriteFile(filepath.Join(dir, proofFile(method)), sig, 0600)
	}
	if err != nil {
		clean()
		return "", nil, err
	}
	return dir, clean, nil
}
func checkArtifact(data []byte, a Artifact) error {
	sum := sha256.Sum256(data)
	if int64(len(data)) != a.Size || hex.EncodeToString(sum[:]) != a.SHA256 {
		return errors.New("release artifact SHA-256 or size mismatch")
	}
	return nil
}
func readBundle(dir string) (Manifest, *os.Root, error) {
	return readBundleWithVerification(dir, SignatureVerification)
}

func readBundleWithVerification(dir, method string) (Manifest, *os.Root, error) {
	method, err := verificationMethod(method)
	if err != nil {
		return Manifest{}, nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return Manifest{}, nil, err
	}
	read := func(name string, max int64) ([]byte, error) {
		f, e := r.Open(name)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		return readLimited(f, max)
	}
	raw, err := read("manifest.txt", MaxManifest)
	if err != nil {
		r.Close()
		return Manifest{}, nil, err
	}
	sig, err := read(proofFile(method), 2048)
	if err != nil {
		r.Close()
		return Manifest{}, nil, err
	}
	m, err := verifyRelease(raw, sig, method, time.Now())
	if err != nil {
		r.Close()
		return Manifest{}, nil, err
	}
	return m, r, nil
}
