// SPDX-License-Identifier: GPL-3.0-or-later

package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func DefaultDirectory() string {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return ""
	}
	return filepath.Join(base, "AgentTail")
}
func privateDirectory(directory string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("native machine credentials require an elevated Administrator terminal")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must not be a symbolic link")
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
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
	return windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, group, dacl, nil)
}
func blob(data []byte) windows.DataBlob {
	b := windows.DataBlob{Size: uint32(len(data))}
	if len(data) > 0 {
		b.Data = &data[0]
	}
	return b
}
func protect(data []byte, credential string, encrypt bool) ([]byte, error) {
	input, entropy := blob(data), blob([]byte("AgentTail/v1/"+credential))
	var result windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &result)
	} else {
		err = windows.CryptUnprotectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &result)
	}
	if err != nil {
		return nil, errors.New("Windows DPAPI credential operation failed")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(result.Data)))
	view := unsafe.Slice(result.Data, int(result.Size))
	output := append([]byte(nil), view...)
	clear(view)
	return output, nil
}
func (s *Store) put(credential string, data []byte) error {
	encrypted, err := protect(data, credential, true)
	if err != nil {
		return err
	}
	defer clear(encrypted)
	return atomicWrite(filepath.Join(s.Dir, credential+".dpapi"), encrypted)
}
func (s *Store) get(credential string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, credential+".dpapi"))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return protect(data, credential, false)
}
func (s *Store) remove(credential string) error {
	err := os.Remove(filepath.Join(s.Dir, credential+".dpapi"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
