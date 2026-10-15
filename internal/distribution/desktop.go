// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type DesktopBundle struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Archive string `json:"archive"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
}
type DesktopManifest struct {
	Schema   int             `json:"schema"`
	Version  string          `json:"version"`
	Sequence uint64          `json:"sequence"`
	Commit   string          `json:"commit"`
	Bundles  []DesktopBundle `json:"bundles"`
}
type DesktopRecord struct {
	Version   string `json:"version"`
	ReleaseID string `json:"release_id"`
	SHA256    string `json:"sha256"`
}

func DesktopSupported() bool {
	return runtime.GOOS == "darwin" && (runtime.GOARCH == "arm64" || runtime.GOARCH == "amd64") || (runtime.GOOS == "linux" || runtime.GOOS == "windows") && runtime.GOARCH == "amd64"
}
func DesktopDefault() bool {
	return DesktopSupported() && (runtime.GOOS != "linux" || os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "")
}
func (m *Manager) desktopRoot() string { return filepath.Join(m.Root, "desktop") }
func (m *Manager) DesktopRecord() (*DesktopRecord, error) {
	data, err := os.ReadFile(filepath.Join(m.desktopRoot(), "installation.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record DesktopRecord
	if json.Unmarshal(data, &record) != nil || !safeVersion.MatchString(record.Version) || !digestPattern.MatchString(record.SHA256) || record.ReleaseID != record.Version+"-"+record.SHA256[:16] {
		return nil, errors.New("invalid desktop installation record")
	}
	return &record, nil
}
func desktopExecutable(root string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(root, "AgentTail.app", "Contents", "MacOS", "agenttail-desktop")
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(root, "agenttail-desktop.exe")
	}
	return filepath.Join(root, "agenttail-desktop")
}
func (m *Manager) DesktopExecutable() (string, error) {
	r, err := m.DesktopRecord()
	if err != nil {
		return "", err
	}
	if r == nil {
		return "", errors.New("the desktop manager is not installed; run agenttail gui install")
	}
	return desktopExecutable(filepath.Join(m.desktopRoot(), "releases", r.ReleaseID)), nil
}

func (m *Manager) InstallDesktop(ctx context.Context, bundle string) (*DesktopRecord, error) {
	if !DesktopSupported() {
		return nil, fmt.Errorf("the desktop manager is unavailable for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	cli, err := m.Record()
	if err != nil {
		return nil, err
	}
	if cli == nil {
		return nil, errors.New("install AgentTail before installing its desktop manager")
	}
	if cli.VerificationMethod() != ChecksumVerification {
		return nil, errors.New("install from the current HTTPS/SHA-256 channel before adding the desktop manager")
	}
	client, transport := releaseClient()
	defer transport.CloseIdleConnections()
	local := false
	if bundle != "" {
		if info, e := os.Lstat(filepath.Join(bundle, "desktop.json")); e == nil {
			if !info.Mode().IsRegular() {
				return nil, errors.New("invalid desktop bundle metadata")
			}
			local = true
		}
	}
	read := func(name string, limit int64) ([]byte, error) {
		var body io.ReadCloser
		var e error
		if local {
			path := filepath.Join(bundle, name)
			info, e := os.Lstat(path)
			if e != nil {
				return nil, e
			}
			if !info.Mode().IsRegular() {
				return nil, errors.New("desktop bundle contains a non-regular file")
			}
			body, e = os.Open(path)
			if e != nil {
				return nil, e
			}
		} else {
			body, e = releaseFile(ctx, client, cli.Source, name)
			if e != nil {
				return nil, e
			}
		}
		defer body.Close()
		return readLimited(body, limit)
	}
	raw, err := read("desktop.json", 64*1024)
	if err != nil {
		return nil, err
	}
	proof, err := read("desktop.json.sha256", 256)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if string(proof) != hex.EncodeToString(digest[:])+"  desktop.json\n" {
		return nil, errors.New("desktop metadata checksum mismatch")
	}
	var manifest DesktopManifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Schema != 1 || manifest.Version != cli.Version || manifest.Sequence != cli.Sequence || len(manifest.Commit) != 40 || len(manifest.Bundles) < 1 || len(manifest.Bundles) > 8 {
		return nil, errors.New("desktop bundle does not match the installed CLI; update or reinstall AgentTail")
	}
	if _, err := hex.DecodeString(manifest.Commit); err != nil {
		return nil, errors.New("invalid desktop source revision")
	}
	var selected *DesktopBundle
	seen := map[string]bool{}
	for i := range manifest.Bundles {
		item := &manifest.Bundles[i]
		key := item.OS + "-" + item.Arch
		ext := ".tar.gz"
		if item.OS == "windows" {
			ext = ".zip"
		}
		if seen[key] || (item.OS != "linux" && item.OS != "darwin" && item.OS != "windows") || (item.Arch != "amd64" && item.Arch != "arm64") || item.Arch != "amd64" && item.OS != "darwin" || item.Archive != "agenttail-desktop-"+key+ext || item.Bytes < 1 || item.Bytes > 24*1024*1024 || !digestPattern.MatchString(item.SHA256) {
			return nil, errors.New("invalid desktop bundle entry")
		}
		seen[key] = true
		if item.OS == runtime.GOOS && item.Arch == runtime.GOARCH {
			selected = item
		}
	}
	if selected == nil {
		return nil, errors.New("a desktop bundle is not available for this platform")
	}
	data, err := read(selected.Archive, selected.Bytes)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	if int64(len(data)) != selected.Bytes || hex.EncodeToString(hash[:]) != selected.SHA256 {
		return nil, errors.New("desktop bundle checksum mismatch")
	}
	root := m.desktopRoot()
	if err = secureInstallDirectory(root); err != nil {
		return nil, err
	}
	releases := filepath.Join(root, "releases")
	if err = secureInstallDirectory(releases); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(releases, ".desktop-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	if err = extractDesktop(data, stage, runtime.GOOS); err != nil {
		return nil, err
	}
	if err = os.Chmod(stage, 0755); err != nil {
		return nil, err
	}
	executable := desktopExecutable(stage)
	check, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(check, executable, "--version", "--json").Output()
	if err != nil {
		return nil, errors.New("desktop manager could not start; install the required desktop graphics libraries")
	}
	var version struct {
		OK   bool `json:"ok"`
		Data struct {
			Version   string `json:"version"`
			Component string `json:"component"`
		} `json:"data"`
	}
	if json.Unmarshal(output, &version) != nil || !version.OK || version.Data.Version != cli.Version || version.Data.Component != "desktop" {
		return nil, errors.New("desktop executable version mismatch")
	}
	if runtime.GOOS == "darwin" {
		if err = exec.CommandContext(check, "/usr/bin/codesign", "--verify", "--deep", "--strict", filepath.Join(stage, "AgentTail.app")).Run(); err != nil {
			return nil, errors.New("desktop application signature is invalid")
		}
	}
	record := &DesktopRecord{Version: cli.Version, ReleaseID: cli.Version + "-" + selected.SHA256[:16], SHA256: selected.SHA256}
	destination := filepath.Join(releases, record.ReleaseID)
	pending := filepath.Join(root, "pending.json")
	if info, e := os.Lstat(destination); e == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("desktop release destination is not a directory")
		}
		existing, e := m.DesktopRecord()
		if e != nil {
			return nil, e
		}
		if existing == nil || existing.ReleaseID != record.ReleaseID {
			var journal DesktopRecord
			data, err := os.ReadFile(pending)
			if err != nil || json.Unmarshal(data, &journal) != nil || journal != *record {
				return nil, errors.New("unmanaged desktop release already exists")
			}
		}
		if err = secureInstallDirectory(destination); err != nil {
			return nil, err
		}
		current, err := os.ReadFile(desktopExecutable(destination))
		if err != nil {
			return nil, err
		}
		prepared, err := os.ReadFile(executable)
		if err != nil {
			return nil, err
		}
		if sha256.Sum256(current) != sha256.Sum256(prepared) {
			return nil, errors.New("installed desktop files differ; close the manager, run agenttail gui uninstall, then agenttail gui install")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	} else {
		if err = writeJSON(pending, record); err != nil {
			return nil, err
		}
		if err = os.Rename(stage, destination); err != nil {
			return nil, err
		}
	}
	if err = m.desktopShortcut(record, true); err != nil {
		return nil, err
	}
	if err = writeJSON(filepath.Join(root, "installation.json"), record); err != nil {
		return nil, err
	}
	_ = os.Remove(pending)
	return record, nil
}

func (m *Manager) RemoveDesktop() error {
	r, err := m.DesktopRecord()
	if err != nil {
		return err
	}
	if r == nil {
		data, e := os.ReadFile(filepath.Join(m.desktopRoot(), "pending.json"))
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		var pending DesktopRecord
		if json.Unmarshal(data, &pending) != nil || !safeVersion.MatchString(pending.Version) || !digestPattern.MatchString(pending.SHA256) || pending.ReleaseID != pending.Version+"-"+pending.SHA256[:16] {
			return errors.New("invalid pending desktop installation record")
		}
		r = &pending
	}
	if err = m.desktopShortcut(r, false); err != nil {
		return err
	}
	_, err = removeReleaseTree(m.desktopRoot())
	return err
}
