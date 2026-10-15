// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func extractDesktop(data []byte, root, system string) error {
	var total int64
	count := 0
	seen := map[string]bool{}
	write := func(name string, size int64, directory bool, source io.Reader) error {
		name = strings.TrimSuffix(name, "/")
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\:\x00") {
			return errors.New("unsafe desktop archive path")
		}
		allowed := name == "GPL-3.0.txt" || name == "THIRD_PARTY_NOTICES.txt" || name == "agenttail.svg" || system == "darwin" && (name == "AgentTail.app" || strings.HasPrefix(name, "AgentTail.app/")) || system == "linux" && name == "agenttail-desktop" || system == "windows" && name == "agenttail-desktop.exe"
		if !allowed || size < 0 || size > 64*1024*1024 {
			return errors.New("unexpected desktop archive entry")
		}
		count++
		total += size
		if count > 128 || total > 96*1024*1024 || seen[name] {
			return errors.New("desktop archive exceeds limits or repeats an entry")
		}
		seen[name] = true
		target := filepath.Join(root, filepath.FromSlash(name))
		if directory {
			return os.MkdirAll(target, 0755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if name == "agenttail-desktop" || name == "agenttail-desktop.exe" || name == "AgentTail.app/Contents/MacOS/agenttail-desktop" {
			mode = 0755
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		if err = f.Chmod(mode); err != nil {
			_ = f.Close()
			return err
		}
		n, err := io.CopyN(f, source, size)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if n != size {
			return io.ErrUnexpectedEOF
		}
		return closeErr
	}
	if system == "windows" {
		packed, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
		for _, item := range packed.File {
			if item.Mode()&os.ModeSymlink != 0 || !item.Mode().IsRegular() && !item.FileInfo().IsDir() {
				return errors.New("desktop archives cannot contain links or special files")
			}
			source, err := item.Open()
			if err != nil {
				return err
			}
			err = write(item.Name, int64(item.UncompressedSize64), item.FileInfo().IsDir(), source)
			_ = source.Close()
			if err != nil {
				return err
			}
		}
	} else {
		compressed, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer compressed.Close()
		packed := tar.NewReader(compressed)
		for {
			item, err := packed.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if item.Typeflag != tar.TypeReg && item.Typeflag != tar.TypeDir {
				return errors.New("desktop archives cannot contain links or special files")
			}
			if err = write(item.Name, item.Size, item.Typeflag == tar.TypeDir, packed); err != nil {
				return err
			}
		}
	}
	executable := "agenttail-desktop"
	if system == "windows" {
		executable += ".exe"
	}
	if system == "darwin" {
		executable = "AgentTail.app/Contents/MacOS/agenttail-desktop"
	}
	for _, required := range []string{executable, "GPL-3.0.txt", "THIRD_PARTY_NOTICES.txt", "agenttail.svg"} {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(required)))
		if !seen[required] || err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return errors.New("desktop archive is incomplete")
		}
	}
	// The bootstrap uses umask 077. These are public application bundles;
	// every directory must be traversable by the ordinary desktop user.
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0755)
		}
		return nil
	})
}
