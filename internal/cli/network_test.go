// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/agent"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
)

func TestActivationWaitsForRecovery(t *testing.T) {
	for _, problem := range []string{"NETWORK", "CONFIGURATION", "CONFLICT", "QUOTA_EXCEEDED"} {
		t.Run(problem, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			states := []agent.Status{
				{State: "error", Desired: "up", Problem: problem},
				{State: "connecting", Desired: "up"},
				// An interface without a valid lease must never count as success.
				{State: "up", Desired: "up", Authorized: false},
				{State: "up", Desired: "up", Authorized: true, Address: "100.96.0.27"},
			}
			calls := 0
			got, err := waitForActivation(ctx, time.Millisecond, func(context.Context) (agent.Status, error) {
				if calls >= len(states) {
					t.Fatal("did not finish after activation")
				}
				state := states[calls]
				calls++
				return state, nil
			})
			if err != nil || calls != len(states) || got.Address != "100.96.0.27" || !got.Authorized {
				t.Fatalf("activation did not wait for recovery: calls=%d, status=%+v, err=%v", calls, got, err)
			}
		})
	}
}

func TestActivationStopsOnRevocationOrDown(t *testing.T) {
	for _, test := range []struct {
		name  string
		state agent.Status
		code  string
	}{
		{"revoked", agent.Status{State: "unauthorized", Desired: "down", Problem: "UNAUTHENTICATED"}, "UNAUTHENTICATED"},
		{"killed", agent.Status{State: "error", Desired: "down", Problem: "KILLED"}, "KILLED"},
		{"stopped", agent.Status{State: "down", Desired: "down"}, "CONFLICT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			calls := 0
			_, err := waitForActivation(ctx, time.Hour, func(context.Context) (agent.Status, error) {
				calls++
				return test.state, nil
			})
			var p *api.Error
			if calls != 1 || !errors.As(err, &p) || p.Code != test.code {
				t.Fatalf("terminal status was not returned immediately: calls=%d, err=%v", calls, err)
			}
		})
	}
}

func TestActivationDeadlineRetainsLastProblem(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, err := waitForActivation(ctx, time.Hour, func(context.Context) (agent.Status, error) {
		return agent.Status{State: "error", Desired: "up", Problem: "CONFIGURATION"}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || got.Problem != "CONFIGURATION" || got.State == "up" {
		t.Fatalf("pending activation was reported as success or lost its error: status=%+v, err=%v", got, err)
	}
}

func TestActivationContextReachesBlockedStatusRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := waitForActivation(ctx, time.Hour, func(request context.Context) (agent.Status, error) {
		<-request.Done()
		return agent.Status{}, &api.Error{Code: "AGENT_OFFLINE", Message: "synthetic IPC timeout"}
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("IPC error hid the activation deadline: %v", err)
	}
}

func TestActivationCancellationAndLocalFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := waitForActivation(ctx, time.Hour, func(context.Context) (agent.Status, error) {
		t.Fatal("polled after cancellation")
		return agent.Status{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was lost", err)
	}
	want := &api.Error{Code: "AGENT_OFFLINE", Message: "synthetic stopped service"}
	request, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_, err = waitForActivation(request, time.Hour, func(context.Context) (agent.Status, error) {
		return agent.Status{}, want
	})
	if err != want {
		t.Fatal("local service failure was hidden", err)
	}
}
