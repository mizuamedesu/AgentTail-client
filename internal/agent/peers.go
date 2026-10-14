package agent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail/internal/netdev"
	"github.com/mizuamedesu/AgentTail/internal/transport"
)

type peerState struct {
	info           KeyInfo
	attempt        *attempt
	active         *connection
	lastOffer      string
	forceRelay     bool
	relayTCP       bool
	flowRetryAfter time.Time
	lastError      string
	retryAt        time.Time
	sent, received uint64
}
type attempt struct {
	generation string
	relay      bool
	relayTCP   bool
	provider   string
	network    netip.Prefix
	cancel     context.CancelFunc
	answer     chan transport.Description
	ice        *transport.ICE // accessed under Key.mu
	stage      string         // accessed under Key.mu; never contains credentials
}
type connection struct {
	ice        *transport.ICE
	credential *relayCredential
}
type relayCredential struct {
	id       string
	provider string
	servers  []transport.ICEServer
	gate     *transport.LeaseGate
	refresh  time.Time
	created  time.Time
}

func (k *Key) applyConfiguration(c configuration) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.desired.Load() || !k.gate.Valid() {
		return nil
	}
	if k.network == nil {
		if prefix, err := netdev.Network(k.cidr); err == nil && prefix != netdev.AddressPool && !k.options.LoopbackOnly {
			if err := netdev.CheckNetwork(prefix); err != nil {
				return err
			}
		}
		network, err := k.options.Factory(k.id, k.private, c.Key.Address)
		if err != nil {
			return err
		}
		k.network = network
	}
	wanted := map[string]KeyInfo{}
	for _, p := range c.Peers {
		wanted[p.ID] = p
	}
	for id, old := range k.peers {
		p, exists := wanted[id]
		if !exists || old.info.Instance != p.Instance || old.info.Public != p.Public || old.info.Address != p.Address {
			k.removePeerLocked(id, old)
		}
	}
	for _, info := range c.Peers {
		if p := k.peers[info.ID]; p != nil {
			p.info = info
			continue
		}
		if err := k.network.SetPeer(info.ID, info.Public, info.Address); err != nil {
			return err
		}
		k.peers[info.ID] = &peerState{info: info}
	}
	seenOffers := map[string]bool{}
	for _, s := range c.Signals {
		p := k.peers[s.Source]
		if p == nil || p.info.Instance != s.Instance {
			continue
		}
		if _, err := uuid.Parse(s.Generation); err != nil {
			continue
		}
		if s.Kind == "answer" && k.id < p.info.ID && p.attempt != nil && p.attempt.generation == s.Generation {
			select {
			case p.attempt.answer <- s.Description:
			default:
			}
		}
		// Only the lexicographically smaller key initiates ICE. Instance IDs and
		// generation IDs prevent simultaneous offers and stale answer reuse.
		if s.Kind != "offer" || k.id < p.info.ID || seenOffers[s.Source] {
			continue
		}
		seenOffers[s.Source] = true
		if p.lastOffer == s.Generation {
			continue
		}
		p.lastOffer = s.Generation
		// A delayed relay offer from before quota exhaustion must not replace
		// an in-progress direct recovery with an unauthorized relay attempt.
		if hasRelay(s.Description) && !k.relayAllowed.Load() {
			continue
		}
		k.startAttemptLocked(p, s.Generation, &s.Description, hasRelay(s.Description))
	}
	for _, p := range k.peers {
		if k.id < p.info.ID && p.attempt == nil && p.active == nil && !time.Now().Before(p.retryAt) {
			k.startAttemptLocked(p, uuid.NewString(), nil, p.forceRelay && k.relayAllowed.Load())
		}
	}
	return nil
}

func (k *Key) removePeerLocked(id string, p *peerState) {
	if k.network != nil {
		_ = k.network.RemovePeer(id)
	}
	if p.attempt != nil {
		p.attempt.cancel()
		if p.attempt.ice != nil {
			p.attempt.ice.Close()
		}
		p.attempt = nil
	}
	k.closeActiveLocked(p)
	k.retiredSent += p.sent
	k.retiredReceived += p.received
	delete(k.peers, id)
}
func (k *Key) closeActiveLocked(p *peerState) {
	if p.active == nil {
		return
	}
	stats := p.active.ice.Stats()
	p.sent += stats.Sent
	p.received += stats.Received
	p.active.ice.Close()
	p.active = nil
	if k.network != nil {
		k.network.DisconnectPeer(p.info.ID)
	}
}
func (k *Key) stopNetwork() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.network == nil {
		return
	}
	for id, p := range k.peers {
		k.removePeerLocked(id, p)
	}
	k.network.Close()
	k.network = nil
}
func (k *Key) startAttemptLocked(p *peerState, generation string, offer *transport.Description, relay bool) {
	relay = relay || k.options.ForceRelayForTest
	if p.attempt != nil {
		p.attempt.cancel()
		if p.attempt.ice != nil {
			p.attempt.ice.Close()
		}
	}
	timeout := 45 * time.Second
	if k.options.AttemptTimeoutForTest > 0 {
		timeout = k.options.AttemptTimeoutForTest
	}
	ctx, cancel := context.WithTimeout(k.ctx, timeout)
	a := &attempt{generation: generation, relay: relay, relayTCP: relay && p.relayTCP, cancel: cancel, answer: make(chan transport.Description, 1), stage: "gather"}
	a.provider = "flow"
	if time.Now().Before(p.flowRetryAfter) || offer != nil && offer.RelayProvider == "cloudflare" {
		a.provider = "cloudflare"
	}
	a.network, _ = netdev.Network(k.cidr)
	if relay {
		a.stage = "turn"
	}
	p.attempt = a
	info := p.info
	k.work.Add(1)
	go func() {
		defer k.work.Done()
		defer cancel()
		ice, credential, err := k.connect(ctx, info, a, offer)
		k.mu.Lock()
		current := k.peers[info.ID]
		// Superseded/cancelled work must not revive a peer. An attempt's own
		// deadline is a connection failure, though: it still needs TURN fallback.
		if current != p || p.attempt != a || k.ctx.Err() != nil || errors.Is(ctx.Err(), context.Canceled) || !k.gate.Valid() || !k.desired.Load() || k.network == nil {
			if ice != nil {
				ice.Close()
			}
			if current == p && p.attempt == a {
				p.attempt = nil
				p.retryAt = time.Now().Add(3 * time.Second)
			}
			k.mu.Unlock()
			k.RequestSync()
			return
		}
		p.attempt = nil
		if err != nil || ctx.Err() != nil {
			if ice != nil {
				ice.Close()
			}
			p.forceRelay = true
			if credential != nil && credential.provider == "flow" && (a.relayTCP || a.stage == "gather" || a.stage == "turn") {
				p.flowRetryAfter = time.Now().Add(5 * time.Minute)
			}
			if a.relay && a.stage == "connect" {
				p.relayTCP = true
			}
			p.lastError = strings.ToUpper(a.stage) + "_FAILED"
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				p.lastError = strings.ToUpper(a.stage) + "_TIMEOUT"
			}
			p.retryAt = time.Now().Add(5 * time.Second)
			k.mu.Unlock()
			k.RequestSync()
			return
		}
		if ice.Stats().Relay {
			if credential == nil || !credential.gate.Valid() || !k.relayAllowed.Load() {
				ice.Close()
				p.retryAt = time.Now().Add(5 * time.Second)
				k.mu.Unlock()
				return
			}
		}
		link := &transport.Guarded{Datagram: ice, Lease: &k.gate, Budget: &k.budget, PathAllowed: func() bool {
			return !ice.Stats().Relay || credential != nil && credential.gate.Valid() && k.relayAllowed.Load()
		}}
		// Keep the current connection until its replacement is ready.
		if old := p.active; old != nil {
			stats := old.ice.Stats()
			p.sent += stats.Sent
			p.received += stats.Received
		}
		if err = k.network.ConnectPeer(info.ID, link); err == nil {
			p.active = &connection{ice: ice, credential: credential}
			p.forceRelay = ice.Stats().Relay
			if !p.forceRelay {
				p.relayTCP = false
				p.flowRetryAfter = time.Time{}
			}
			p.lastError = ""
		} else {
			ice.Close()
			p.active = nil
			p.lastError = "ACTIVATE_FAILED"
		}
		k.mu.Unlock()
		k.RequestSync()
	}()
}

func (k *Key) connect(ctx context.Context, peer KeyInfo, a *attempt, offer *transport.Description) (*transport.ICE, *relayCredential, error) {
	servers := append([]transport.ICEServer(nil), k.options.STUN...)
	var credential *relayCredential
	var err error
	if a.relay {
		credential, err = k.turn(ctx, a.provider)
		if err != nil {
			return nil, nil, err
		}
		servers = append(servers, credential.servers...)
	}
	k.setAttemptStage(a, "gather")
	ice, err := transport.NewICE(transport.ICEOptions{Servers: servers, LoopbackOnly: k.options.LoopbackOnly, RelayOnly: a.relay && k.options.RelayOnlyForTest, RelayTCPFallback: a.relayTCP,
		ExcludePrefix: a.network, InterfaceFilter: func(name string) bool { return !netdev.IsVPNInterface(name) }})
	if err != nil {
		return nil, credential, err
	}
	k.mu.Lock()
	if p := k.peers[peer.ID]; p == nil || p.attempt != a {
		k.mu.Unlock()
		ice.Close()
		return nil, credential, context.Canceled
	}
	a.ice = ice
	k.mu.Unlock()
	gather, cancel := context.WithTimeout(ctx, 8*time.Second)
	description, err := ice.Gather(gather)
	cancel()
	if err != nil {
		return ice, credential, err
	}
	if len(description.Candidates) > 32 {
		description.Candidates = description.Candidates[:32]
	}
	if credential != nil && hasRelay(description) {
		description.RelayProvider = credential.provider
	}
	kind := "offer"
	if offer != nil {
		kind = "answer"
	}
	input := map[string]any{"instance_id": k.instance, "target_key_id": peer.ID, "target_instance": peer.Instance, "generation": a.generation, "kind": kind, "description": description}
	k.setAttemptStage(a, "signal")
	if err = k.control(ctx, "POST", "/api/agent/signal", input, nil, "signal-"+a.generation+"-"+kind); err != nil {
		return ice, credential, err
	}
	var remote transport.Description
	if offer != nil {
		remote = *offer
	} else {
		k.setAttemptStage(a, "answer")
		select {
		case <-ctx.Done():
			return ice, credential, ctx.Err()
		case remote = <-a.answer:
		}
	}
	if hasRelay(remote) && credential == nil {
		return ice, credential, errors.New("relay candidate needs a valid local relay authorization")
	}
	connectionContext, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	k.setAttemptStage(a, "connect")
	err = ice.Connect(connectionContext, remote, offer == nil)
	return ice, credential, err
}

func (k *Key) setAttemptStage(a *attempt, stage string) {
	k.mu.Lock()
	a.stage = stage
	k.mu.Unlock()
}

func hasRelay(d transport.Description) bool {
	for _, c := range d.Candidates {
		if strings.Contains(c, " typ relay") {
			return true
		}
	}
	return false
}

func (k *Key) expireConnections() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, p := range k.peers {
		if p.active == nil {
			continue
		}
		failed := false
		select {
		case <-p.active.ice.Done():
			failed = true
		default:
		}
		isRelay := p.active.ice.Stats().Relay
		credential := p.active.credential
		if isRelay && (credential == nil || !credential.gate.Valid() || !k.relayAllowed.Load()) {
			failed = true
		}
		if failed {
			k.closeActiveLocked(p)
			p.forceRelay = true
			k.RequestSync()
			continue
		}
		if isRelay && time.Now().After(credential.refresh) && k.id < p.info.ID && p.attempt == nil && !time.Now().Before(p.retryAt) {
			k.startAttemptLocked(p, uuid.NewString(), nil, true)
		}
	}
}

func (k *Key) turn(ctx context.Context, preferred string) (*relayCredential, error) {
	k.relayMu.Lock()
	defer k.relayMu.Unlock()
	if !k.relayAllowed.Load() {
		return nil, errors.New("relay disabled by the control server")
	}
	if preferred != "cloudflare" {
		preferred = "flow"
		if time.Now().Before(k.flowRetryAfter) {
			preferred = "cloudflare"
		}
	}
	if c := k.relay; c != nil && c.provider == preferred && c.gate.Valid() && time.Now().Before(c.refresh) {
		return c, nil
	}
	if time.Now().Before(k.relayRetry) {
		return nil, errors.New("relay credential retry is paced")
	}
	start := time.Now()
	var result struct {
		Servers  []transport.ICEServer `json:"iceServers"`
		TTL      int                   `json:"ttl_seconds"`
		ID       string                `json:"credential_id"`
		Rate     int                   `json:"bytes_per_second"`
		Provider string                `json:"provider"`
	}
	input := map[string]string{"instance_id": k.instance}
	if preferred == "cloudflare" {
		input["provider"] = preferred
	}
	err := k.control(ctx, "POST", "/api/agent/turn", input, &result, "")
	if err != nil {
		k.relayRetry = time.Now().Add(20 * time.Second)
		return nil, err
	}
	if result.TTL < 20 || result.TTL > 60 || len(result.Servers) == 0 || result.ID == "" || result.Rate < 1 {
		return nil, errors.New("invalid TURN response")
	}
	// Older control servers only issued Cloudflare credentials.
	if result.Provider == "" {
		result.Provider = "cloudflare"
	}
	if result.Provider != "flow" && result.Provider != "cloudflare" || preferred == "cloudflare" && result.Provider != preferred {
		return nil, errors.New("unexpected TURN provider")
	}
	if result.Provider == "flow" {
		k.flowRetryAfter = time.Time{}
	} else if !time.Now().Before(k.flowRetryAfter) {
		k.flowRetryAfter = time.Now().Add(5 * time.Minute)
	}
	gate := &transport.LeaseGate{}
	gate.Renew(start, time.Duration(result.TTL-1)*time.Second)
	c := &relayCredential{id: result.ID, provider: result.Provider, servers: result.Servers, gate: gate, created: start, refresh: start.Add(time.Duration(result.TTL-20) * time.Second)}
	k.relay = c
	return c, nil
}
func (k *Key) reconcileRelay(active []string) {
	if !k.relayAllowed.Load() {
		// Polling must enforce the same cancellation as a relay.stopped event,
		// including a credential-rotation attempt that has not connected yet.
		k.stopRelay()
		return
	}
	allowed := map[string]bool{}
	for _, id := range active {
		allowed[id] = true
	}
	k.relayMu.Lock()
	// An issuance racing this snapshot can be absent once; the next sync checks
	// it. Provider revocation still takes effect independently of this client.
	if c := k.relay; c != nil && (!k.relayAllowed.Load() || !allowed[c.id] && time.Since(c.created) > 10*time.Second) {
		c.gate.Stop()
		k.relay = nil
	}
	k.relayMu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, p := range k.peers {
		if c := p.active; c != nil && c.ice.Stats().Relay && (!k.relayAllowed.Load() || c.credential == nil || !allowed[c.credential.id] && time.Since(c.credential.created) > 10*time.Second) {
			if c.credential != nil {
				c.credential.gate.Stop()
			}
			k.closeActiveLocked(p)
		}
	}
}
func (k *Key) stopRelay() {
	k.relayMu.Lock()
	if k.relay != nil {
		k.relay.gate.Stop()
		k.relay = nil
	}
	k.relayMu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, p := range k.peers {
		if !k.relayAllowed.Load() {
			p.forceRelay = false
			p.relayTCP = false
			p.flowRetryAfter = time.Time{}
			p.retryAt = time.Time{}
		}
		if p.attempt != nil && p.attempt.relay {
			p.attempt.cancel()
			if p.attempt.ice != nil {
				p.attempt.ice.Close()
			}
			p.attempt = nil
		}
		if p.active != nil && p.active.ice.Stats().Relay {
			if p.active.credential != nil {
				p.active.credential.gate.Stop()
			}
			k.closeActiveLocked(p)
		}
	}
}
