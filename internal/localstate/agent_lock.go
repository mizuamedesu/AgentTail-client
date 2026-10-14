package localstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

var ErrAgentRunning = errors.New("an agent is already running for this state directory")

// AgentLock prevents a second daemon from unlinking the active IPC socket or
// reading the same key credentials into a competing local instance.
func (s *State) AgentLock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.Store.Dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = tryLockFile(f); err != nil {
		f.Close()
		if lockBusy(err) {
			return nil, ErrAgentRunning
		}
		return nil, err
	}
	return func() { unlockFile(f); f.Close() }, nil
}

// WaitAgentLock waits for a stopped service to finish closing its tunnels and
// release its lock. It never removes the lock file or signals another process.
func (s *State) WaitAgentLock(ctx context.Context) (func(), error) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		unlock, err := s.AgentLock()
		if !errors.Is(err, ErrAgentRunning) {
			return unlock, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}
