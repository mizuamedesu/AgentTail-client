package distribution

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"
)

const launcherMarker = "rem AgentTail managed launcher\r\n"

func locations() (string, string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", "", err
	}
	root := filepath.Join(base, "AgentTail")
	return root, filepath.Join(root, "agenttail.cmd"), nil
}
func secureInstallDirectory(path string) error {
	if !windows.GetCurrentProcessToken().IsElevated() || !filepath.IsAbs(path) {
		return errors.New("installation requires Administrator privileges")
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	for p := path; ; p = filepath.Dir(p) {
		i, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("install path contains a reparse point")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	group, _, err := sd.Group()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, group, dacl, nil)
}
func (m *Manager) ownsLauncher() (bool, error) {
	i, err := os.Lstat(m.Launcher)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !i.Mode().IsRegular() {
		return false, errUnmanagedLauncher
	}
	b, err := os.ReadFile(m.Launcher)
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(string(b), "@echo off\r\n"+launcherMarker) {
		return false, errUnmanagedLauncher
	}
	return true, nil
}
func (m *Manager) activate(r *Record) error {
	if _, err := m.ownsLauncher(); err != nil {
		return err
	}
	if strings.ContainsAny(m.executable(r), "%\r\n\"!") {
		return errors.New("unsupported characters in install path")
	}
	data := "@echo off\r\n" + launcherMarker + "\"" + m.executable(r) + "\" %*\r\nexit /b %errorlevel%\r\n"
	if err := atomicFile(m.Launcher, []byte(data), 0644); err != nil {
		return err
	}
	return machinePath(m.Root, true)
}
func (m *Manager) removeLauncher() error {
	exists, err := m.ownsLauncher()
	if err != nil {
		return err
	}
	if exists {
		if err = os.Remove(m.Launcher); err != nil {
			return err
		}
	}
	return machinePath(m.Root, false)
}
func (m *Manager) serviceExecutable(r *Record) string { return m.executable(r) }
func machinePath(path string, add bool) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	v, kind, err := k.GetStringValue("Path")
	if err != nil {
		return err
	}
	entries := strings.Split(v, ";")
	var result []string
	found := false
	for _, e := range entries {
		if strings.EqualFold(strings.TrimRight(e, `\`), strings.TrimRight(path, `\`)) {
			found = true
			if !add {
				continue
			}
		}
		result = append(result, e)
	}
	if add && !found {
		result = append(result, path)
	}
	value := strings.Join(result, ";")
	if kind == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", value)
	} else {
		err = k.SetStringValue("Path", value)
	}
	if err != nil {
		return err
	}
	msg, _ := windows.UTF16PtrFromString("Environment")
	var ignored uintptr
	windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW").Call(0xffff, 0x1a, 0, uintptr(unsafe.Pointer(msg)), 2, 5000, uintptr(unsafe.Pointer(&ignored)))
	return nil
}
func removeReleaseTree(dir string) (bool, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		paths = append(paths, path)
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	slices.Reverse(paths)
	deferred := false
	for _, p := range paths {
		if err = os.Remove(p); err == nil || errors.Is(err, os.ErrNotExist) {
			continue
		}
		from, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return deferred, e
		}
		if e = windows.MoveFileEx(from, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); e != nil {
			return deferred, e
		}
		deferred = true
	}
	return deferred, nil
}
