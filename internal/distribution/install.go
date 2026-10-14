// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/agent"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/service"
)

type Record struct {
	Version   string `json:"version"`
	Sequence  uint64 `json:"sequence"`
	Digest    string `json:"manifest_sha256"`
	ReleaseID string `json:"release_id"`
	StateDir  string `json:"state_dir"`
	Source    string `json:"source"`
	Service   bool   `json:"service_installed"`
}
type Manager struct {
	Root, Launcher string
	State          *localstate.State
}

var errUnmanagedLauncher = errors.New("command is not managed by AgentTail")

func New(state *localstate.State) (*Manager, error) {
	root, launcher, err := locations()
	if err != nil {
		return nil, err
	}
	if err = secureInstallDirectory(root); err != nil {
		return nil, err
	}
	return &Manager{Root: root, Launcher: launcher, State: state}, nil
}

// Installed reads an existing installation without creating or repairing its
// directories. Informational update checks must not alter the installation.
func Installed(state *localstate.State) (*Record, error) {
	root, launcher, err := locations()
	if err != nil {
		return nil, err
	}
	return (&Manager{Root: root, Launcher: launcher, State: state}).Record()
}
func (m *Manager) Record() (*Record, error) {
	data, err := os.ReadFile(filepath.Join(m.Root, "installation.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err = json.Unmarshal(data, &r); err != nil {
		return nil, errors.New("invalid installation record")
	}
	if err = m.validateRecord(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
func (m *Manager) validateRecord(r *Record) error {
	if r == nil {
		return nil
	}
	if !safeVersion.MatchString(r.Version) || r.Sequence == 0 || !digestPattern.MatchString(r.Digest) || r.ReleaseID != r.Version+"-"+r.Digest[:16] || filepath.Clean(r.StateDir) != filepath.Clean(m.State.Store.Dir) {
		return errors.New("installation record is invalid or belongs to a different state directory")
	}
	return ValidateSource(r.Source)
}
func (m *Manager) executable(r *Record) string {
	// Keep the private release basename compatible with older signed updaters.
	// The public command and downloaded artifacts are named agenttail.
	name := "vpn"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(m.Root, "releases", r.ReleaseID, name)
}

func (m *Manager) legacyLauncher() (*Manager, bool, error) {
	legacy := *m
	name := "vpn"
	if runtime.GOOS == "windows" {
		name += ".cmd"
	}
	legacy.Launcher = filepath.Join(m.Root, name)
	if legacy.Launcher == m.Launcher {
		return &legacy, false, nil
	}
	owned, err := legacy.ownsLauncher()
	if errors.Is(err, errUnmanagedLauncher) {
		return &legacy, false, nil // Never touch another program named vpn.
	}
	return &legacy, owned, err
}

func (m *Manager) removeLegacyLauncher() error {
	legacy, owned, err := m.legacyLauncher()
	if err != nil || !owned {
		return err
	}
	return os.Remove(legacy.Launcher)
}

// Older updaters can install new bytes while retaining their vpn launcher.
// Re-running the installer repairs that layout without replacing credentials.
func (m *Manager) ensureLauncher(ctx context.Context, r *Record) error {
	// Also repair installations made under the bootstrap's private umask by
	// older installers, even when the same-version launcher already exists.
	info, err := os.Lstat(m.executable(r))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("installed executable is not a regular file")
	}
	for _, dir := range []string{m.Root, filepath.Join(m.Root, "releases")} {
		if err := secureInstallDirectory(dir); err != nil {
			return err
		}
	}
	owned, err := m.ownsLauncher()
	if err != nil {
		return err
	}
	_, legacyOwned, err := m.legacyLauncher()
	if err != nil {
		return err
	}
	if !owned || legacyOwned {
		// Repair the same-version launcher before inspecting the service: the
		// BusyBox service validates its executable even when being stopped.
		if err = m.activate(r); err != nil {
			return err
		}
		if err = m.stopAgent(ctx, r.Service); err != nil {
			return err
		}
		if r.Service {
			if err = service.Install(m.serviceExecutable(r), r.StateDir); err != nil {
				return err
			}
		}
	}
	return m.removeLegacyLauncher()
}

// A native stop request can return while the old agent still holds its lock.
// Pending recovery also needs to wait when launchd has already removed its job.
func (m *Manager) stopAgent(ctx context.Context, managed bool) error {
	status, err := service.Inspect()
	if err != nil {
		return err
	}
	if status.Running {
		if err = service.Stop(); err != nil {
			return err
		}
		managed = true
	}
	var unlock func()
	if managed {
		wait, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		unlock, err = m.State.WaitAgentLock(wait)
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return errors.New("agent did not stop within 30 seconds; stop any foreground agenttail agent before retrying")
		}
	} else {
		unlock, err = m.State.AgentLock()
		if errors.Is(err, localstate.ErrAgentRunning) {
			return errors.New("stop the foreground agenttail agent before updating or installing")
		}
	}
	if err != nil {
		return err
	}
	unlock()
	return nil
}
func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicFile(path, append(data, '\n'), 0644)
}
func atomicFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".agenttail-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
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

// Recover restores the previous version if the process died during activation.
// The journal is retained on rollback failure, making the failure reviewable.
func (m *Manager) Recover(ctx context.Context) error {
	data, err := os.ReadFile(filepath.Join(m.Root, "pending.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal struct{ Old, New *Record }
	if json.Unmarshal(data, &journal) != nil || journal.New == nil {
		return errors.New("invalid pending installation journal")
	}
	if err = m.validateRecord(journal.Old); err != nil {
		return err
	}
	if err = m.validateRecord(journal.New); err != nil {
		return err
	}
	if journal.Old != nil {
		if err = m.stopAgent(ctx, journal.Old.Service || journal.New.Service); err != nil {
			return err
		}
		if err = m.activate(journal.Old); err != nil {
			return err
		}
		if journal.Old.Service {
			if err = service.Install(m.serviceExecutable(journal.Old), journal.Old.StateDir); err != nil {
				return err
			}
		}
		if err = writeJSON(filepath.Join(m.Root, "installation.json"), journal.Old); err != nil {
			return err
		}
	} else {
		if journal.New.Service {
			if err = service.Uninstall(); err != nil {
				return err
			}
			if err = m.stopAgent(ctx, true); err != nil {
				return err
			}
		}
		if err = m.removeLauncher(); err != nil {
			return err
		}
		if err = os.Remove(filepath.Join(m.Root, "installation.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(filepath.Join(m.Root, "pending.json"))
}

func (m *Manager) Apply(ctx context.Context, bundle, source string, noService, updating bool) (*Record, error) {
	unlock, err := localstate.OperationLock(filepath.Join(m.Root, "update.lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = m.Recover(ctx); err != nil {
		return nil, err
	}
	old, err := m.Record()
	if err != nil {
		return nil, err
	}
	if updating && old == nil {
		return nil, errors.New("no managed installation exists; run the installer first")
	}
	if !updating && old != nil {
		return nil, errors.New("AgentTail is already installed; use agenttail update")
	}
	if old == nil {
		status, e := service.Inspect()
		if e != nil {
			return nil, e
		}
		if status.Installed {
			return nil, errors.New("an unmanaged AgentTail service exists; remove that service before installing")
		}
	}
	manifest, root, err := readBundle(bundle)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if old != nil {
		if manifest.Digest == old.Digest {
			return old, m.ensureLauncher(ctx, old)
		}
		if manifest.Sequence <= old.Sequence {
			return nil, errors.New("release rollback or sequence reuse refused")
		}
		noService = !old.Service
	}
	if source == "" {
		source = DefaultSource
		if old != nil {
			source = old.Source
		}
	}
	if err = ValidateSource(source); err != nil {
		return nil, err
	}
	next := &Record{Version: manifest.Version, Sequence: manifest.Sequence, Digest: manifest.Digest, ReleaseID: manifest.Version + "-" + manifest.Digest[:16], StateDir: m.State.Store.Dir, Source: source, Service: !noService}
	if err = m.stage(manifest, root, next); err != nil {
		return nil, err
	}
	// Only a verified executable under the protected installation directory is
	// granted access to existing Keychain entries. Plaintext never crosses here.
	config, err := m.State.Read()
	if err != nil {
		return nil, err
	}
	scopes := []string{"session/account", "session/admin"}
	for _, k := range config.Keys {
		scopes = append(scopes, "key/"+k.ID)
	}
	if err = m.State.Store.AuthorizeExecutable(m.executable(next), scopes); err != nil {
		return nil, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	probeOutput, probeError := exec.CommandContext(checkCtx, m.executable(next), "--state-dir", m.State.Store.Dir, "--json", "_check-secrets").Output()
	cancel()
	var probe struct {
		OK   bool `json:"ok"`
		Data struct {
			Version  string `json:"version"`
			Readable bool   `json:"native_credentials_readable"`
		} `json:"data"`
	}
	if probeError != nil || json.Unmarshal(probeOutput, &probe) != nil || !probe.OK || !probe.Data.Readable || probe.Data.Version != next.Version {
		return nil, errors.New("verified new executable cannot read the existing native credentials; current installation retained")
	}
	if err = writeJSON(filepath.Join(m.Root, "pending.json"), map[string]any{"Old": old, "New": next}); err != nil {
		return nil, err
	}
	commitErr := func() error {
		if e := m.stopAgent(ctx, old != nil && old.Service); e != nil {
			return e
		}
		if e := m.activate(next); e != nil {
			return e
		}
		if next.Service {
			if e := service.Install(m.serviceExecutable(next), next.StateDir); e != nil {
				return e
			}
			deadline := time.Now().Add(15 * time.Second)
			for {
				probe, cancel := context.WithTimeout(ctx, time.Second)
				e := agent.LocalRequest(probe, next.StateDir, "", "status", nil)
				cancel()
				if e == nil {
					current, inspectErr := service.Inspect()
					if inspectErr == nil && current.Running {
						break
					}
				}
				if time.Now().After(deadline) {
					current, inspectErr := service.Inspect()
					if inspectErr != nil {
						return fmt.Errorf("new service did not become healthy: %w", inspectErr)
					}
					if current.LastFailure != "" {
						return fmt.Errorf("new service did not become healthy; last failure: %s", current.LastFailure)
					}
					if e != nil {
						return fmt.Errorf("new service did not become healthy: %w", e)
					}
					return errors.New("new service did not become healthy")
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(200 * time.Millisecond):
				}
			}
		}
		return writeJSON(filepath.Join(m.Root, "installation.json"), next)
	}()
	if commitErr != nil {
		if rollback := m.Recover(context.WithoutCancel(ctx)); rollback != nil {
			return nil, fmt.Errorf("activation failed (%v); rollback also failed (%v); pending.json retained", commitErr, rollback)
		}
		return nil, fmt.Errorf("activation failed and was rolled back: %w", commitErr)
	}
	if err = os.Remove(filepath.Join(m.Root, "pending.json")); err != nil {
		return nil, err
	}
	return next, m.removeLegacyLauncher()
}

func (m *Manager) stage(manifest Manifest, bundle *os.Root, next *Record) error {
	files, err := manifest.Platform(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	versions := filepath.Join(m.Root, "releases")
	if err = secureInstallDirectory(versions); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(versions, ".staged-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0755); err != nil {
		return err
	}
	for _, a := range files {
		f, e := bundle.Open(a.Name)
		if e != nil {
			return e
		}
		mode := os.FileMode(0644)
		if a.Role == "vpn" {
			mode = 0755
		}
		e = writeArtifact(filepath.Join(dir, installedName(a)), f, a, mode)
		f.Close()
		if e != nil {
			return e
		}
	}
	if err = atomicFile(filepath.Join(dir, "manifest.txt"), manifest.Raw, 0644); err != nil {
		return err
	}
	if err = atomicFile(filepath.Join(dir, "manifest.sig"), manifest.Signature, 0644); err != nil {
		return err
	}
	dest := filepath.Join(versions, next.ReleaseID)
	if _, err = os.Lstat(dest); err == nil {
		// A previous activation or Keychain probe may have failed after staging.
		// Reuse only a byte-identical signed version under the protected root.
		for _, a := range files {
			f, e := os.Open(filepath.Join(dest, installedName(a)))
			if e != nil {
				return e
			}
			e = copyArtifact(io.Discard, f, a)
			f.Close()
			if e != nil {
				return e
			}
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(dir, dest)
}

// Remove runs after the CLI has revoked credentials and removed native secrets.
// Old Windows executable files may remain locked until process exit; the OS
// schedules their removal at reboot and reports that fact to the caller.
func (m *Manager) Remove(ctx context.Context, before func(*Record) error) (bool, error) {
	unlock, err := localstate.OperationLock(filepath.Join(m.Root, "update.lock"))
	if err != nil {
		return false, err
	}
	defer unlock()
	if err = m.Recover(ctx); err != nil {
		return false, err
	}
	r, err := m.Record()
	if err != nil {
		return false, err
	}
	if r == nil {
		return false, errors.New("no managed installation exists")
	}
	if err = before(r); err != nil {
		return false, err
	}
	if r.Service {
		if err = service.Uninstall(); err != nil {
			return false, err
		}
	}
	if err = m.removeLauncher(); err != nil {
		return false, err
	}
	if err = m.removeLegacyLauncher(); err != nil {
		return false, err
	}
	deferred, err := removeReleaseTree(filepath.Join(m.Root, "releases"))
	if err != nil {
		return deferred, err
	}
	if err = os.Remove(filepath.Join(m.Root, "installation.json")); err != nil {
		return deferred, err
	}
	return deferred, nil
}
