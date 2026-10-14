// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
)

func ipcPath(directory string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(directory))))
	return `\\.\pipe\AgentTail-` + hex.EncodeToString(sum[:16])
}
func listenIPC(directory string) (net.Listener, error) {
	return winio.ListenPipe(ipcPath(directory), &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)", InputBufferSize: 4096, OutputBufferSize: 4096})
}
func dialIPC(ctx context.Context, directory string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, ipcPath(directory))
}
