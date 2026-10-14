package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestUpdateNoticeOutputAndFailure(t *testing.T) {
	for _, mode := range []string{"new release", "current", "offline", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			var output bytes.Buffer
			output.WriteString("command result\n")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			writeUpdateNotice(ctx, &output, "0.1.0-dev.17", "https://updates.example.invalid", 17, "cache.json", func(checkCtx context.Context, source, current string, sequence uint64, cachePath string) (string, error) {
				deadline, ok := checkCtx.Deadline()
				if !ok || time.Until(deadline) > updateNoticeTimeout || source != "https://updates.example.invalid" || current != "0.1.0-dev.17" || sequence != 17 || cachePath != "cache.json" {
					t.Fatal("update check lost its timeout or installation information")
				}
				switch mode {
				case "offline":
					return "", errors.New("network unavailable")
				case "current":
					return "", nil
				}
				return "0.1.0-dev.18", nil
			})
			if mode == "new release" {
				if !strings.HasPrefix(output.String(), "command result\n\nUpdate available: 0.1.0-dev.17 → 0.1.0-dev.18\n") || !strings.Contains(output.String(), "Run agenttail update") {
					t.Fatal("tip must appear after the command result and provide the update command")
				}
			} else if output.String() != "command result\n" {
				t.Fatal("no update, errors and cancellation must remain silent")
			}
		})
	}
}

func TestUpdateNoticeCommandSelection(t *testing.T) {
	root := &cobra.Command{Use: "agenttail"}
	for _, name := range []string{"version", "help", "install", "update", "uninstall", "licenses", "_check-secrets"} {
		root.AddCommand(&cobra.Command{Use: name, Hidden: strings.HasPrefix(name, "_"), Run: func(*cobra.Command, []string) {}})
	}
	for _, groupName := range []string{"vpn", "agent", "completion", "skills"} {
		group := &cobra.Command{Use: groupName}
		name := "status"
		if groupName == "skills" {
			name = "install"
		}
		group.AddCommand(&cobra.Command{Use: name, Run: func(*cobra.Command, []string) {}})
		root.AddCommand(group)
	}
	for _, test := range []struct {
		path []string
		want bool
	}{
		{[]string{"version"}, true}, {[]string{"vpn", "status"}, true}, {[]string{"skills", "install"}, true},
		{[]string{"help"}, false}, {[]string{"install"}, false}, {[]string{"update"}, false},
		{[]string{"uninstall"}, false}, {[]string{"licenses"}, false}, {[]string{"_check-secrets"}, false},
		{[]string{"agent", "status"}, false}, {[]string{"completion", "status"}, false}, {[]string{"vpn"}, false},
	} {
		cmd, _, err := root.Find(test.path)
		if err != nil || updateNoticeAllowed(cmd, false, true) != test.want {
			t.Errorf("wrong notification mode for %v: %v", test.path, err)
		}
		if updateNoticeAllowed(cmd, true, true) || updateNoticeAllowed(cmd, false, false) {
			t.Errorf("JSON or piped command attempted an update check: %v", test.path)
		}
	}
	version, _, _ := root.Find([]string{"version"})
	version.Flags().Bool("help", true, "help")
	if updateNoticeAllowed(version, false, true) {
		t.Fatal("--help must not perform an update check")
	}
}
