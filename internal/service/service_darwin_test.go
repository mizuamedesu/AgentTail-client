package service

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"
)

func launchdTestExit(code int) error {
	return exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", code)).Run()
}

func TestLaunchdStopWaitsForRemovalAndAcceptsRetry(t *testing.T) {
	missing := launchdTestExit(113)
	for _, code := range []int{0, 3, 36} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			bootoutErr := launchdTestExit(code)
			prints, bootouts := 0, 0
			command := func(ctx context.Context, args ...string) error {
				if args[1] != "system/"+Name {
					t.Fatalf("wrong target: %v", args)
				}
				if args[0] == "bootout" {
					bootouts++
					return bootoutErr
				}
				prints++
				if prints < 3 {
					return nil
				}
				return missing
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := stopLaunchd(ctx, command); err != nil {
				t.Fatal(err)
			}
			if prints != 3 || bootouts != 1 {
				t.Fatalf("did not wait for removal: %d polls, %d stops", prints, bootouts)
			}
		})
	}
}

func TestLaunchdStopPreservesErrorsAndBoundsWait(t *testing.T) {
	denied := launchdTestExit(1)
	for _, verb := range []string{"bootout", "print"} {
		err := stopLaunchd(context.Background(), func(_ context.Context, args ...string) error {
			if args[0] == verb {
				return denied
			}
			return nil
		})
		if !errors.Is(err, denied) {
			t.Fatalf("%s error was hidden: %v", verb, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := stopLaunchd(ctx, func(context.Context, ...string) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unload wait was not bounded: %v", err)
	}
}
