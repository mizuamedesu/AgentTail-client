// SPDX-License-Identifier: GPL-3.0-or-later

package platform

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func StartDesktopHelper(executable, session, state string) error {
	file, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	parameters, err := windows.UTF16PtrFromString(strings.Join([]string{"--state-dir", windows.EscapeArg(state), "desktop-helper", "--session-file", windows.EscapeArg(session)}, " "))
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	info := shellExecuteInfo{Mask: 0x40, Verb: verb, File: file, Parameters: parameters, Show: 0}
	info.Size = uint32(unsafe.Sizeof(info))
	result, _, _ := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 || info.Process == 0 {
		return errors.New("administrator approval was declined or the helper could not start")
	}
	return windows.CloseHandle(info.Process)
}
