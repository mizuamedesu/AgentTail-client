// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func (m *Manager) desktopShortcut(record *DesktopRecord, add bool) error {
	production, _, err := locations()
	if err != nil {
		return err
	}
	entry := "/Applications/AgentTail.app"
	if m.Root != production {
		entry = filepath.Join(m.Root, "desktop-links", "AgentTail.app")
	}
	source := filepath.Join(m.desktopRoot(), "releases", record.ReleaseID, "AgentTail.app")
	known := []string{source}
	previous, err := m.DesktopRecord()
	if err != nil {
		return err
	}
	if previous != nil && previous.ReleaseID != record.ReleaseID {
		known = append(known, filepath.Join(m.desktopRoot(), "releases", previous.ReleaseID, "AgentTail.app"))
	}
	exists := false
	if _, err = os.Lstat(entry); err == nil {
		exists = true
		managed, e := managedDesktopApplication(entry, known)
		if e != nil {
			return e
		}
		if !managed {
			if !add {
				return nil
			}
			return errors.New("existing AgentTail application is not managed by this installer")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !add {
		if !exists {
			return nil
		}
		if m.Root == production {
			if err = registerDesktopApplication(entry, false); err != nil {
				return err
			}
		}
		return os.RemoveAll(entry)
	}

	// Finder/Launchpad must see a real application bundle in /Applications.
	// The old symlink into /Library/AgentTail was not reliably discovered.
	parent := filepath.Dir(entry)
	if info, e := os.Lstat(parent); errors.Is(e, os.ErrNotExist) {
		if err = os.MkdirAll(parent, 0755); err != nil {
			return err
		}
		if err = os.Chmod(parent, 0755); err != nil {
			return err
		}
	} else if e != nil {
		return e
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("application menu path is not a directory")
	}
	want, err := desktopApplicationDigest(source)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".agenttail-app-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err = os.CopyFS(stage, os.DirFS(source)); err != nil {
		return err
	}
	// CopyFS applies the bootstrap umask. Restore the public bundle modes;
	// no signed resources are added or modified during installation.
	if err = filepath.WalkDir(stage, func(path string, item fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if item.IsDir() || info.Mode().Perm()&0111 != 0 {
			mode = 0755
		}
		return os.Chmod(path, mode)
	}); err != nil {
		return err
	}
	got, err := desktopApplicationDigest(stage)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("copied desktop application differs from the verified bundle")
	}
	if exists {
		// Exchange works for both the dev.22 link and a previous app directory.
		// A failed or interrupted exchange leaves the previous app usable.
		err = unix.RenamexNp(stage, entry, unix.RENAME_SWAP)
	} else {
		err = os.Rename(stage, entry)
	}
	if err != nil {
		return err
	}
	if m.Root == production {
		return registerDesktopApplication(entry, true)
	}
	return nil
}

func managedDesktopApplication(entry string, known []string) (bool, error) {
	info, err := os.Lstat(entry)
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(entry)
		if err != nil {
			return false, err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(entry), target)
		}
		for _, candidate := range known {
			if filepath.Clean(target) == filepath.Clean(candidate) {
				return true, nil
			}
		}
		return false, nil
	}
	if !info.IsDir() {
		return false, nil
	}
	got, err := desktopApplicationDigest(entry)
	if err != nil {
		return false, nil
	}
	for _, candidate := range known {
		want, err := desktopApplicationDigest(candidate)
		if err == nil && got == want {
			return true, nil
		}
	}
	return false, nil
}

func desktopApplicationDigest(root string) ([sha256.Size]byte, error) {
	hash := sha256.New()
	err := filepath.WalkDir(root, func(path string, item fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		if item.IsDir() {
			fmt.Fprintf(hash, "directory\x00%s\x00", relative)
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("desktop application contains a non-regular file")
		}
		fmt.Fprintf(hash, "file\x00%s\x00%d\x00%d\x00", relative, info.Mode().Perm()&0111, info.Size())
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(hash, file)
		_ = file.Close()
		return err
	})
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, err
}

func registerDesktopApplication(entry string, add bool) error {
	const tool = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	option := "-u"
	if add {
		option = "-f"
	}
	command := []string{tool, option, entry}
	if os.Geteuid() == 0 {
		uid, _ := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
		if uid == 0 {
			if info, err := os.Stat("/dev/console"); err == nil {
				if stat, ok := info.Sys().(*syscall.Stat_t); ok {
					uid = uint64(stat.Uid)
				}
			}
		}
		if uid != 0 {
			user := strconv.FormatUint(uid, 10)
			command = append([]string{"/bin/launchctl", "asuser", user, "/usr/bin/sudo", "-n", "-H", "-u", "#" + user, "--"}, command...)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("macOS application registration failed for %s: %w: %s", entry, err, output)
	}
	return nil
}
