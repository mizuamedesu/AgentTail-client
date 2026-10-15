// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import "golang.org/x/sys/windows"

func protectSessionDirectory(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
