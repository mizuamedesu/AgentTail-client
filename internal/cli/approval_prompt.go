// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"golang.org/x/term"
)

// Open only the already validated approval URL, including the locally computed
// recipient fragment. Never build a shell command from a URL or a BROWSER value.
func approvalBrowser() func(context.Context, string) error {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return nil
	}
	var program string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		program = "/usr/bin/open"
	case "windows":
		program, args = "rundll32.exe", []string{"url.dll,FileProtocolHandler"}
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return nil
		}
		program = "xdg-open"
	default:
		return nil
	}
	path, err := exec.LookPath(program)
	if err != nil {
		return nil
	}
	return func(ctx context.Context, link string) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		// VPN commands may run via sudo. Open the GUI as the invoking user.
		if runtime.GOOS != "windows" && os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
			return exec.CommandContext(ctx, "sudo", "-n", "-u", os.Getenv("SUDO_USER"), "--", path, link).Run()
		}
		return exec.CommandContext(ctx, path, append(args, link)...).Run()
	}
}

func (o *options) promptAuthorization(kind, link, code, fingerprint string, deadline time.Time) error {
	ctx, cancel := context.WithDeadline(o.ctx, deadline)
	defer cancel()
	var input *os.File
	var browser func(context.Context, string) error
	if o.browser && term.IsTerminal(int(os.Stderr.Fd())) {
		browser = approvalBrowser()
		if browser != nil {
			// curl | sh consumes stdin. Read Enter from the controlling terminal,
			// never from the installation script or another redirected input.
			name := "/dev/tty"
			if runtime.GOOS == "windows" {
				name = "CONIN$"
			}
			input, _ = os.Open(name)
		}
	}
	var reader io.Reader
	if input != nil {
		defer input.Close()
		reader = input
	}
	err := authorizationPrompt(ctx, os.Stderr, reader, browser, kind, link, code, fingerprint)
	if errors.Is(err, context.DeadlineExceeded) && o.ctx.Err() == nil {
		return &api.Error{Code: "EXPIRED_TOKEN", Message: "Approval expired; run the command again"}
	}
	return err
}

func authorizationPrompt(ctx context.Context, output io.Writer, input io.Reader, browser func(context.Context, string) error, kind, link, code, fingerprint string) error {
	fmt.Fprintf(output, "\n! First, copy your one-time code: %s\n\n", code)
	opened := false
	if input != nil && browser != nil {
		address, err := url.Parse(link)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Press Enter to open %s in your browser... ", address.Host)
		entered := make(chan error, 1)
		go func() {
			_, err := bufio.NewReader(input).ReadString('\n')
			entered <- err
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-entered:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == nil {
				opened = browser(ctx, link) == nil
			}
		}
		fmt.Fprintln(output)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !opened {
		fmt.Fprintf(output, "Open this link in your browser:\n\n  %s\n\nRecipient fingerprint: %s\n\n", link, fingerprint)
	}
	fmt.Fprintf(output, "Waiting for %s approval. Keep this terminal open.\n", kind)
	return nil
}
