package agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail/internal/netdev"
	"github.com/mizuamedesu/AgentTail/internal/transport"
)

// No network operation is expected: the peer already exists in this snapshot.
// Embedding the interface makes an unexpected network operation fail the test.
type untouchedNetwork struct{ netdev.Interface }

func TestDelayedRelayOfferPreservesDirectRecovery(t *testing.T) {
	var canceled atomic.Bool
	existing := &attempt{generation: uuid.NewString(), cancel: func() { canceled.Store(true) }}
	peer := &peerState{info: KeyInfo{ID: "a", Instance: uuid.NewString()}, attempt: existing}
	k := &Key{id: "b", ctx: context.Background(), network: &untouchedNetwork{}, peers: map[string]*peerState{"a": peer}}
	defer k.work.Wait()
	k.desired.Store(true)
	k.gate.Renew(time.Now(), 30*time.Second)
	config := configuration{Peers: []KeyInfo{peer.info}, Signals: []Signal{{
		Source: "a", Instance: peer.info.Instance, Generation: uuid.NewString(), Kind: "offer",
		Description: transport.Description{Candidates: []string{"1 1 udp 1 127.0.0.1 1234 typ relay"}},
	}}}
	if err := k.applyConfiguration(config); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	preserved := peer.attempt == existing
	k.mu.Unlock()
	if !preserved || canceled.Load() {
		t.Fatal("an obsolete relay offer canceled direct recovery after quota exhaustion")
	}
}

func TestRelayDisabledSnapshotCancelsPendingRotation(t *testing.T) {
	var canceled atomic.Bool
	gate := &transport.LeaseGate{}
	gate.Renew(time.Now(), 30*time.Second)
	peer := &peerState{forceRelay: true, retryAt: time.Now().Add(time.Minute), attempt: &attempt{relay: true, cancel: func() { canceled.Store(true) }}}
	k := &Key{peers: map[string]*peerState{"a": peer}, relay: &relayCredential{gate: gate}}
	k.reconcileRelay(nil) // Polling observes the limit; notification was lost.
	if gate.Valid() || k.relay != nil || peer.attempt != nil || !canceled.Load() || peer.forceRelay || !peer.retryAt.IsZero() {
		t.Fatal("polling did not stop the pending relay rotation and permit direct recovery")
	}
}
