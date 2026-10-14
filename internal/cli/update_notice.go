// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/distribution"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const updateNoticeTimeout = 1500 * time.Millisecond

func updateNoticeAllowed(cmd *cobra.Command, json, interactive bool) bool {
	if cmd == nil || json || !interactive || cmd.Hidden || cmd.Run == nil && cmd.RunE == nil {
		return false
	}
	if help, _ := cmd.Flags().GetBool("help"); help || cmd.Name() == "help" {
		return false
	}
	top := cmd
	for top.Parent() != nil && top.Parent().Parent() != nil {
		top = top.Parent()
	}
	switch top.Name() {
	case "agent", "completion", "install", "update", "uninstall", "licenses":
		return false
	}
	return true
}

func (o *options) showUpdateNotice(cmd *cobra.Command) {
	interactive := term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
	if o.ctx.Err() != nil || !updateNoticeAllowed(cmd, o.json, interactive) {
		return
	}
	source := distribution.DefaultSource
	var sequence uint64
	cacheDir, err := os.UserCacheDir()
	if o.state != nil {
		record, recordErr := distribution.Installed(o.state)
		if recordErr != nil {
			return
		}
		if record != nil {
			source, sequence = record.Source, record.Sequence
		}
		cacheDir, err = o.state.Store.Dir, nil
	}
	cachePath := ""
	if err == nil {
		cachePath = filepath.Join(cacheDir, "agenttail-update-check", fmt.Sprintf("%x.json", sha256.Sum256([]byte(source))))
	}
	writeUpdateNotice(o.ctx, os.Stderr, o.version, source, sequence, cachePath, distribution.AvailableUpdate)
}

func writeUpdateNotice(ctx context.Context, output io.Writer, current, source string, sequence uint64, cachePath string,
	check func(context.Context, string, string, uint64, string) (string, error)) {
	ctx, cancel := context.WithTimeout(ctx, updateNoticeTimeout)
	defer cancel()
	latest, err := check(ctx, source, current, sequence, cachePath)
	if err == nil && latest != "" && ctx.Err() == nil {
		fmt.Fprintf(output, "\nUpdate available: %s → %s\nRun agenttail update to install the latest version.\n", current, latest)
	}
}
