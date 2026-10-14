package platform

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"strings"
	"unsafe"
)

type shellExecuteInfo struct {
	Size       uint32
	Mask       uint32
	Window     uintptr
	Verb       *uint16
	File       *uint16
	Parameters *uint16
	Directory  *uint16
	Show       int32
	Instance   uintptr
	IDList     uintptr
	Class      *uint16
	ClassKey   uintptr
	HotKey     uint32
	Icon       uintptr
	Process    windows.Handle
}

func Elevate() (bool, int, error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return false, 0, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, 0, err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return false, 0, err
	}
	args := make([]string, 0, len(os.Args)-1)
	for _, arg := range os.Args[1:] {
		args = append(args, windows.EscapeArg(arg))
	}
	parameters, err := windows.UTF16PtrFromString(strings.Join(args, " "))
	if err != nil {
		return false, 0, err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	info := shellExecuteInfo{Mask: 0x40, Verb: verb, File: file, Parameters: parameters, Show: 1}
	info.Size = uint32(unsafe.Sizeof(info))
	result, _, _ := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 || info.Process == 0 {
		return false, 0, errors.New("administrator elevation was declined or failed")
	}
	defer windows.CloseHandle(info.Process)
	if _, err = windows.WaitForSingleObject(info.Process, windows.INFINITE); err != nil {
		return false, 0, err
	}
	var code uint32
	if err = windows.GetExitCodeProcess(info.Process, &code); err != nil {
		return false, 0, err
	}
	return true, int(code), nil
}
