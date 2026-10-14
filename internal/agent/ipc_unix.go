//go:build linux || darwin

package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
)

func ipcPath(directory string) string { return filepath.Join(directory, "agent.sock") }
func listenIPC(directory string) (net.Listener, error) {
	path := ipcPath(directory)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("agent socket path is occupied by a non-socket file")
		}
		// The exclusive AgentLock is held before removing a stale socket.
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
func dialIPC(ctx context.Context, directory string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", ipcPath(directory))
}
