// SPDX-License-Identifier: GPL-3.0-or-later

package localstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/secrets"
)

func TestWaitAgentLockWaitsForShutdown(t *testing.T) {
	s := &State{Store: &secrets.Store{Dir: t.TempDir()}}
	unlocked, err := s.AgentLock()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unlocked != nil {
			unlocked()
		}
	}()
	if _, err := s.AgentLock(); !errors.Is(err, ErrAgentRunning) {
		t.Fatalf("live agent was not detected: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		unlock, err := s.WaitAgentLock(ctx)
		if err == nil {
			unlock()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("returned before the old agent released its lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unlocked()
	unlocked = nil
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWaitAgentLockLeavesLiveAgentAlone(t *testing.T) {
	s := &State{Store: &secrets.Store{Dir: t.TempDir()}}
	unlock, err := s.AgentLock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err = s.WaitAgentLock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait must be bounded: %v", err)
	}
	if _, err = s.AgentLock(); !errors.Is(err, ErrAgentRunning) {
		t.Fatalf("wait bypassed the live agent lock: %v", err)
	}
}

func TestWaitAgentLockPreservesFilesystemErrors(t *testing.T) {
	s := &State{Store: &secrets.Store{Dir: t.TempDir()}}
	if err := os.Mkdir(filepath.Join(s.Store.Dir, "agent.lock"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WaitAgentLock(context.Background()); err == nil || errors.Is(err, ErrAgentRunning) {
		t.Fatalf("filesystem error was treated as a running agent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.WaitAgentLock(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was ignored: %v", err)
	}
}
