// SPDX-License-Identifier: GPL-3.0-or-later

package sshkeys

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func owned(i os.FileInfo) error {
	if i.Mode()&os.ModeSymlink != 0 {
		return errors.New("SSH files cannot be symbolic links")
	}
	return nil
}
func protect(path string, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;" + inherit + ";FA;;;" + sid + ")(A;" + inherit + ";FA;;;SY)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func lock(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{})
}

// Windows OpenSSH's default Match Group administrators uses a shared file.
// An unelevated administrator must rerun only public-key registration elevated;
// private-key installation always remains in the original user's profile.
func InstallPublicCurrent(home, public string) (string, error) {
	token := windows.GetCurrentProcessToken()
	groups, err := token.GetTokenGroups()
	if err != nil {
		return "", err
	}
	admin := false
	for _, g := range groups.AllGroups() {
		if g.Sid.String() == "S-1-5-32-544" {
			admin = true
		}
	}
	if !admin {
		return InstallPublic(home, public)
	}
	if !token.IsElevated() {
		return "", errors.New("Windows administrator SSH accounts use ProgramData/ssh/administrators_authorized_keys; rerun this public-key command in an Administrator terminal")
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	base := filepath.Join(programData, "ssh")
	info, err := os.Lstat(base)
	if err != nil {
		return "", errors.New("Windows OpenSSH Server directory is missing; install OpenSSH Server first")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("OpenSSH Server directory cannot be a link")
	}
	r, err := os.OpenRoot(base)
	if err != nil {
		return "", err
	}
	defer r.Close()
	permissions := func(path string, _ bool) error {
		sd, e := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
		if e != nil {
			return e
		}
		dacl, _, e := sd.DACL()
		if e != nil {
			return e
		}
		owner, _, e := sd.Owner()
		if e != nil {
			return e
		}
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
	}
	return installAuthorized(r, base, "administrators_authorized_keys", public, permissions)
}
