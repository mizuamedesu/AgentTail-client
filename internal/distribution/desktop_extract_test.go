// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func desktopTar(t *testing.T, extra *tar.Header) []byte {
	t.Helper()
	var data bytes.Buffer
	compressed := gzip.NewWriter(&data)
	packed := tar.NewWriter(compressed)
	if extra != nil {
		if err := packed.WriteHeader(extra); err != nil {
			t.Fatal(err)
		}
		if extra.Size > 0 {
			_, _ = packed.Write([]byte(strings.Repeat("x", int(extra.Size))))
		}
	}
	for _, name := range []string{"agenttail-desktop", "GPL-3.0.txt", "THIRD_PARTY_NOTICES.txt", "agenttail.svg"} {
		payload := []byte("test " + name)
		if err := packed.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(payload)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := packed.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := packed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestDesktopArchiveCannotEscapeOrReplaceFiles(t *testing.T) {
	for _, header := range []*tar.Header{
		{Name: "../outside", Mode: 0644, Typeflag: tar.TypeReg, Size: 1},
		{Name: "/absolute", Mode: 0644, Typeflag: tar.TypeReg, Size: 1},
		{Name: "agenttail-desktop", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "agenttail-desktop", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"},
		{Name: "agenttail-desktop", Typeflag: tar.TypeReg, Mode: 0755, Size: 1},
		{Name: "unexpected-program", Typeflag: tar.TypeReg, Mode: 0755, Size: 1},
		{Name: "C:\\outside", Typeflag: tar.TypeReg, Mode: 0755, Size: 1},
	} {
		t.Run(strings.ReplaceAll(header.Name, "/", "_"), func(t *testing.T) {
			root := t.TempDir()
			destination := filepath.Join(root, "desktop")
			if err := os.Mkdir(destination, 0755); err != nil {
				t.Fatal(err)
			}
			if err := extractDesktop(desktopTar(t, header), destination, "linux"); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Stat(filepath.Join(root, "outside")); !os.IsNotExist(err) {
				t.Fatal("archive escaped its destination")
			}
		})
	}
	root := t.TempDir()
	if err := extractDesktop(desktopTar(t, nil), root, "linux"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "agenttail-desktop")); err != nil || string(data) != "test agenttail-desktop" {
		t.Fatalf("valid archive failed: %v", err)
	}
}

func TestWindowsDesktopArchiveRejectsLinks(t *testing.T) {
	var data bytes.Buffer
	packed := zip.NewWriter(&data)
	header := &zip.FileHeader{Name: "agenttail-desktop.exe", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0755)
	file, err := packed.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("outside"))
	if err := packed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractDesktop(data.Bytes(), t.TempDir(), "windows"); err == nil {
		t.Fatal("symlink accepted from Windows desktop archive")
	}
}
