package agent

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail/internal/api"
	"github.com/mizuamedesu/AgentTail/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail/internal/localstate"
	"github.com/mizuamedesu/AgentTail/internal/netdev"
	"github.com/mizuamedesu/AgentTail/internal/transport"
)

type Key struct {
	options                      Options
	id, public, instance         string
	private                      []byte
	desired                      atomic.Bool
	terminal                     atomic.Bool
	gate                         transport.LeaseGate
	budget                       transport.Budget
	wake                         chan struct{}
	mu                           sync.Mutex // network/peer state only; never held during control requests
	name, address, cidr, problem string
	lastSync                     int64
	network                      netdev.Interface
	peers                        map[string]*peerState
	retiredSent, retiredReceived uint64
	work                         sync.WaitGroup
	relayMu                      sync.Mutex
	relay                        *relayCredential
	relayRetry                   time.Time
	flowRetryAfter               time.Time // protected by relayMu
	relayAllowed                 atomic.Bool
	ctx                          context.Context
}

func NewKey(options Options) (*Key, error) {
	metadata, credential := options.Metadata, options.Credential
	if _, err := uuid.Parse(metadata.ID); err != nil {
		return nil, errors.New("invalid local key ID")
	}
	public, err := cryptobox.PublicFromPrivate(credential.Private)
	if err != nil || credential.KeyID != metadata.ID || public != metadata.Public || credential.Public != public || !strings.HasPrefix(credential.Token, "atk_") || options.Client == nil || options.Client.Token != credential.Token {
		return nil, errors.New("agent credential does not match the selected key")
	}
	if options.Factory == nil {
		options.Factory = netdev.New
	}
	if options.STUN == nil {
		options.STUN = []transport.ICEServer{{URLs: []string{"stun:stun.cloudflare.com:3478"}}}
	}
	k := &Key{options: options, id: metadata.ID, public: public, instance: uuid.NewString(), private: append([]byte(nil), credential.Private...), name: metadata.Name, wake: make(chan struct{}, 1), peers: map[string]*peerState{}}
	// Do not retain a second private-key slice inside Options.
	k.options.Credential.Private = nil
	k.desired.Store(metadata.AutoUp)
	k.budget.Set(1)
	return k, nil
}

func (k *Key) RequestSync() {
	select {
	case k.wake <- struct{}{}:
	default:
	}
}
func (k *Key) SetDesired(up bool) error {
	if up && k.terminal.Load() {
		return &api.Error{Code: "UNAUTHENTICATED", Message: "this key credential was revoked; log in again"}
	}
	// Down always closes the data gate before waiting for disk or network work.
	if !up {
		k.desired.Store(false)
		k.gate.Stop()
		k.stopNetwork()
	}
	if k.options.State != nil {
		if err := k.options.State.Update(func(c *localstate.Config) error {
			for i := range c.Keys {
				if c.Keys[i].ID == k.id {
					c.Keys[i].AutoUp = up
					return nil
				}
			}
			return errors.New("key is no longer authorized locally")
		}); err != nil {
			return err
		}
	}
	k.desired.Store(up)
	k.RequestSync()
	return nil
}
func (k *Key) hardStop(problem string, terminal bool) {
	k.gate.Stop()
	if terminal {
		k.terminal.Store(true)
	}
	_ = k.SetDesired(false)
	k.setProblem(problem)
}
func (k *Key) setProblem(problem string) { k.mu.Lock(); k.problem = problem; k.mu.Unlock() }

func (k *Key) Run(ctx context.Context) {
	k.ctx = ctx
	watchContext, cancel := context.WithCancel(ctx)
	k.work.Add(1)
	go func() {
		defer k.work.Done()
		timer := time.NewTicker(250 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-watchContext.Done():
				return
			case <-timer.C:
				if !k.gate.Valid() {
					k.stopNetwork()
				}
				k.expireConnections()
			}
		}
	}()
	if !k.options.DisableEvents {
		k.work.Add(1)
		go func() { defer k.work.Done(); k.events(watchContext) }()
	}
	defer func() { cancel(); k.gate.Stop(); k.stopNetwork(); k.work.Wait(); clear(k.private) }()
	tick := time.NewTicker(SyncInterval)
	defer tick.Stop()
	k.RequestSync()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-k.wake:
		}
		if k.terminal.Load() {
			continue
		}
		if err := k.synchronize(ctx); err != nil {
			var p *api.Error
			if errors.As(err, &p) && (p.Code == "UNAUTHENTICATED" || p.Code == "FORBIDDEN" || p.Code == "EXPIRED_TOKEN" || p.Code == "KILLED") {
				k.hardStop(p.Code, true)
			} else {
				k.setProblem("NETWORK")
				if errors.As(err, &p) && (p.Code == "CONFLICT" || p.Code == "QUOTA_EXCEEDED" || p.Code == "CONFIGURATION") {
					k.gate.Stop()
					k.stopNetwork()
					k.setProblem(p.Code)
				}
			}
		}
		// Coalesce a burst of signaling notifications without spinning on D1.
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (k *Key) control(ctx context.Context, method, path string, input, output any, idempotency string) error {
	request, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	return k.options.Client.Do(request, method, path, input, output, idempotency)
}
func (k *Key) synchronize(ctx context.Context) error {
	up := k.desired.Load()
	desired := "down"
	if up {
		desired = "up"
	}
	start := time.Now()
	var lease struct {
		TTL      int    `json:"ttl_seconds"`
		KeyID    string `json:"key_id"`
		Instance string `json:"instance_id"`
	}
	if err := k.control(ctx, "POST", "/api/agent/lease", map[string]any{"instance_id": k.instance, "desired_state": desired, "report": k.report()}, &lease, ""); err != nil {
		// A kill switch deliberately rejects an up renewal. Inspect the existing
		// lease so kill disables reboot auto-up until an explicit later command.
		var p *api.Error
		if errors.As(err, &p) && p.Code == "CONFLICT" {
			var c configuration
			if k.control(ctx, "GET", "/api/agent/sync?instance_id="+k.instance, nil, &c, "") == nil && c.Killed {
				k.hardStop("KILLED", false)
				return nil
			}
		}
		return err
	}
	if lease.TTL < 1 || lease.TTL > 60 || lease.KeyID != k.id || lease.Instance != k.instance {
		k.gate.Stop()
		k.stopNetwork()
		return errors.New("invalid lease response")
	}
	var c configuration
	syncStart := time.Now()
	if err := k.control(ctx, "GET", "/api/agent/sync?instance_id="+k.instance, nil, &c, ""); err != nil {
		return err
	}
	if err := c.validate(k.options.Metadata, k.instance); err != nil {
		k.gate.Stop()
		k.stopNetwork()
		return &api.Error{Code: "CONFIGURATION", Message: "VPN configuration validation failed"}
	}
	if c.Key.CIDR == "" {
		c.Key.CIDR = netdev.AddressPool.String()
	}
	if c.Killed {
		k.hardStop("KILLED", false)
		return nil
	}
	if up != k.desired.Load() {
		k.RequestSync()
		return nil
	}
	// A reply extends authorization only after the complete ACL snapshot passes
	// validation, measured from the beginning of the lease request.
	if time.Since(start) >= time.Duration(lease.TTL)*time.Second {
		return errors.New("lease response arrived after its deadline")
	}
	k.mu.Lock()
	rangeChanged := k.network != nil && (k.address != c.Key.Address || k.cidr != c.Key.CIDR)
	k.mu.Unlock()
	if rangeChanged {
		k.gate.Stop()
		k.stopNetwork()
	}
	k.mu.Lock()
	previousName := k.name
	k.name, k.address, k.cidr, k.lastSync, k.problem = c.Key.Name, c.Key.Address, c.Key.CIDR, time.Now().Unix(), ""
	k.mu.Unlock()
	if k.options.State != nil && c.Key.Name != previousName {
		_ = k.options.State.Update(func(config *localstate.Config) error {
			for i := range config.Keys {
				if config.Keys[i].ID == k.id {
					config.Keys[i].Name = c.Key.Name
				}
			}
			return nil
		})
	}
	k.budget.Set(c.Limits.BytesPerSecond / c.Limits.MaxConnections)
	k.relayAllowed.Store(c.RelayAllowed && c.Limits.RelayDisabled == 0)
	k.reconcileRelay(c.ActiveTURN)
	if len(c.Commands) > 0 {
		command := c.Commands[0]
		if command.Action != "sync" && (command.Action == "up") != up {
			if err := k.SetDesired(command.Action == "up"); err != nil {
				return k.acknowledge(ctx, command, "failed", "permission")
			}
			return nil // next cycle leases the new state, then acknowledges it
		}
	}
	var applyErr error
	if up && c.Desired == "up" {
		// D1 expiries are integer seconds; subtract one second so local clock
		// quantization cannot authorize traffic beyond the server's expiry.
		remaining := time.Duration(c.LeaseRemaining-1) * time.Second
		originalDeadline := start.Add(time.Duration(lease.TTL-1) * time.Second)
		if maximum := originalDeadline.Sub(syncStart); remaining > maximum {
			remaining = maximum
		}
		k.gate.Renew(syncStart, remaining)
		applyErr = k.applyConfiguration(c)
	} else {
		k.gate.Stop()
		k.stopNetwork()
	}
	if applyErr != nil {
		k.gate.Stop()
		k.stopNetwork()
		applyErr = &api.Error{Code: "CONFIGURATION", Message: "VPN interface or peer configuration failed"}
	}
	if len(c.Commands) > 0 {
		command := c.Commands[0]
		status, result := "done", command.Action
		if result == "sync" {
			result = "synced"
		}
		if applyErr != nil {
			status, result = "failed", "permission"
		}
		if err := k.acknowledge(ctx, command, status, result); err != nil {
			return err
		}
		k.RequestSync()
	}
	return applyErr
}
func (k *Key) acknowledge(ctx context.Context, c Command, status, result string) error {
	return k.control(ctx, "POST", "/api/agent/commands/"+c.ID+"/ack", map[string]string{"instance_id": k.instance, "status": status, "result": result}, nil, "ack-"+c.ID)
}
func (k *Key) report() map[string]any {
	s := k.Status()
	direct, relay := 0, 0
	for _, p := range s.Peers {
		if p.State == "connected" {
			if p.Path == "relay" {
				relay++
			} else {
				direct++
			}
		}
	}
	state := s.State
	if state != "up" && state != "down" && state != "connecting" {
		state = "error"
	}
	report := map[string]any{"state": state, "direct_peers": direct, "relay_peers": relay, "sent_bytes": min(s.Sent, 9007199254740991), "received_bytes": min(s.Received, 9007199254740991)}
	if info := machine(); info != nil {
		report["machine"] = info
	}
	return report
}
func (k *Key) Status() Status {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := Status{ID: k.id, Name: k.name, Public: k.public, Instance: k.instance, Address: k.address, State: "down", Desired: "down", LastSync: k.lastSync, Problem: k.problem, Authorized: k.gate.Valid(), Peers: []PeerStatus{}, Sent: k.retiredSent, Received: k.retiredReceived, Dropped: k.budget.DroppedBytes()}
	s.CIDR = k.cidr
	if k.desired.Load() {
		s.Desired = "up"
		s.State = "connecting"
	}
	if k.network != nil && s.Authorized {
		s.Interface = k.network.Name()
		s.State = "up"
	}
	if k.terminal.Load() {
		s.State = "unauthorized"
	}
	if k.problem != "" && s.State != "up" && s.State != "unauthorized" {
		s.State = "error"
	}
	for _, p := range k.peers {
		status := PeerStatus{ID: p.info.ID, Name: p.info.Name, Address: p.info.Address, State: "connecting", Sent: p.sent, Received: p.received}
		status.Problem = p.lastError
		if p.attempt != nil {
			status.Stage = p.attempt.stage
		}
		if p.active != nil {
			stats := p.active.ice.Stats()
			status.Sent += stats.Sent
			status.Received += stats.Received
			status.State = "connected"
			status.Path = "direct"
			if stats.Relay {
				status.Path = "relay"
			}
		}
		s.Sent += status.Sent
		s.Received += status.Received
		s.Peers = append(s.Peers, status)
	}
	sort.Slice(s.Peers, func(i, j int) bool { return s.Peers[i].ID < s.Peers[j].ID })
	return s
}
