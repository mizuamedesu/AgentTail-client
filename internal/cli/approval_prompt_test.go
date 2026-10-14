package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

const promptLink = "https://agenttail.mizuame.app/ssh-device?code=ABCD-EFGH#recipient=SHA256:locally-generated-recipient"

func TestAuthorizationPrompt(t *testing.T) {
	for _, mode := range []string{"browser", "headless", "browser failed", "input closed"} {
		t.Run(mode, func(t *testing.T) {
			var output bytes.Buffer
			var input io.Reader = strings.NewReader("\n")
			if mode == "headless" {
				input = nil
			} else if mode == "input closed" {
				input = strings.NewReader("")
			}
			calls := 0
			browser := func(_ context.Context, link string) error {
				calls++
				if link != promptLink {
					t.Fatal("browser URL lost the request code or locally pinned recipient")
				}
				if mode == "browser failed" {
					return errors.New("no browser")
				}
				return nil
			}
			if err := authorizationPrompt(context.Background(), &output, input, browser, "SSH private-key installation", promptLink, "ABCD-EFGH", "SHA256:locally-generated-recipient"); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if !strings.HasPrefix(text, "\n! First, copy your one-time code: ABCD-EFGH\n") || !strings.Contains(text, "Waiting for SSH private-key installation approval") {
				t.Fatal("approval instructions must lead with the code and show that the CLI is waiting")
			}
			if mode == "browser" {
				if calls != 1 || strings.Contains(text, promptLink) {
					t.Fatal("successful browser opening should keep the terminal instructions short")
				}
			} else if !strings.Contains(text, promptLink) {
				t.Fatal("manual fallback must preserve the complete approval link")
			}
			if (mode == "headless" || mode == "input closed") && calls != 0 {
				t.Fatal("must not open a browser without Enter on a terminal")
			}
		})
	}
}

func TestAuthorizationPromptStopsWaitingAtExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	var output bytes.Buffer
	err := authorizationPrompt(ctx, &output, input, func(context.Context, string) error {
		t.Error("must not open an expired approval")
		return nil
	}, "VPN device", promptLink, "ABCD-EFGH", "SHA256:locally-generated-recipient")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting for Enter did not expire: %v", err)
	}
}
