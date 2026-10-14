// Package transport carries already-encrypted WireGuard datagrams over ICE.
// No account, application payload, or private WireGuard key is available here.
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
)

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Description is exchanged only over the authenticated, ACL-checked control API.
// The ICE password is a short-lived secret and must not be logged.
type Description struct {
	Ufrag         string   `json:"ufrag"`
	Password      string   `json:"password"`
	Candidates    []string `json:"candidates"`
	RelayProvider string   `json:"relay_provider,omitempty"`
}

type ICEOptions struct {
	Servers   []ICEServer
	RelayOnly bool
	// RelayTCPFallback avoids local UDP paths after relay negotiation fails.
	// UDP-only providers retain their existing candidates.
	RelayTCPFallback bool
	ExcludePrefix    netip.Prefix
	InterfaceFilter  func(string) bool
	LoopbackOnly     bool // local fixtures only; production candidates exclude loopback
}

type ICE struct {
	agent    *ice.Agent
	conn     *ice.Conn
	mu       sync.Mutex
	relay    atomic.Bool
	sent     atomic.Uint64
	received atomic.Uint64
	close    sync.Once
	done     chan struct{}
	doneOnce sync.Once
}

type Stats struct {
	Relay    bool   `json:"relay"`
	Sent     uint64 `json:"wireguard_bytes_sent"`
	Received uint64 `json:"wireguard_bytes_received"`
}

func NewICE(options ICEOptions) (*ICE, error) {
	var urls []*stun.URI
	for _, server := range options.Servers {
		for _, raw := range server.URLs {
			u, err := stun.ParseURI(raw)
			if err != nil {
				return nil, errors.New("invalid ICE server URL")
			}
			u.Username, u.Password = server.Username, server.Credential
			urls = append(urls, u)
		}
	}
	if options.RelayTCPFallback {
		var tcp []*stun.URI
		for _, u := range urls {
			if (u.Scheme == stun.SchemeTypeTURN || u.Scheme == stun.SchemeTypeTURNS) && u.Proto == stun.ProtoTypeTCP {
				tcp = append(tcp, u)
			}
		}
		if len(tcp) > 0 {
			// Keeping host/srflx candidates here can select the same failing UDP
			// path again, even when TCP/TLS relay candidates are responding.
			urls = tcp
			options.RelayOnly = true
		}
	}
	if options.RelayOnly && len(urls) == 0 {
		return nil, errors.New("relay mode requires TURN credentials")
	}
	opts := []ice.AgentOption{
		ice.WithLoggerFactory(&logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}),
		ice.WithUrls(urls),
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6}),
		ice.WithSTUNGatherTimeout(6 * time.Second),
		ice.WithRelayAcceptanceMinWait(1500 * time.Millisecond),
		ice.WithDisconnectedTimeout(5 * time.Second),
		ice.WithFailedTimeout(10 * time.Second),
		ice.WithKeepaliveInterval(2 * time.Second),
		ice.WithIPFilter(func(ip net.IP) bool {
			// Loopback TURN fixtures must not bind allocations to external
			// NICs or depend on the runner's LAN routing.
			if options.LoopbackOnly {
				return ip.IsLoopback()
			}
			// Never advertise VPN addresses as ICE underlay candidates.
			return !virtualAddress(ip) && !inPrefix(options.ExcludePrefix, ip) && !ip.IsLoopback()
		}),
		ice.WithRemoteIPFilter(func(ip net.IP) bool {
			if options.LoopbackOnly {
				return ip.IsLoopback()
			}
			return !virtualAddress(ip) && !inPrefix(options.ExcludePrefix, ip) && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback()
		}),
	}
	if options.InterfaceFilter != nil {
		opts = append(opts, ice.WithInterfaceFilter(options.InterfaceFilter))
	}
	if options.RelayOnly {
		opts = append(opts, ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeRelay}))
	}
	if options.LoopbackOnly {
		opts = append(opts, ice.WithIncludeLoopback())
	}
	agent, err := ice.NewAgentWithOptions(opts...)
	if err != nil {
		return nil, err
	}
	s := &ICE{agent: agent, done: make(chan struct{})}
	if err := agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		if state == ice.ConnectionStateFailed || state == ice.ConnectionStateClosed {
			s.doneOnce.Do(func() { close(s.done) })
		}
	}); err != nil {
		agent.Close()
		return nil, err
	}
	if err := agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		s.relay.Store(local.Type() == ice.CandidateTypeRelay || remote.Type() == ice.CandidateTypeRelay)
	}); err != nil {
		agent.Close()
		return nil, err
	}
	return s, nil
}

func (s *ICE) Gather(ctx context.Context) (Description, error) {
	if err := ctx.Err(); err != nil {
		return Description{}, err
	}
	done := make(chan struct{})
	if err := s.agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			close(done)
		}
	}); err != nil {
		return Description{}, err
	}
	if err := s.agent.GatherCandidates(); err != nil {
		return Description{}, err
	}
	select {
	case <-ctx.Done():
	case <-done:
	}
	// Gathering covers every interface and server. A stalled TURN allocation
	// must not discard candidates already obtained through a working path.
	// Explicit cancellation still aborts the attempt; only its gathering budget
	// may end with a usable partial description. The ICE agent stays alive for
	// connectivity checks and is closed by the caller when the attempt ends.
	if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return Description{}, err
	}
	ufrag, password, err := s.agent.GetLocalUserCredentials()
	if err != nil {
		return Description{}, err
	}
	candidates, err := s.agent.GetLocalCandidates()
	if err != nil {
		return Description{}, err
	}
	if len(candidates) == 0 {
		if err := ctx.Err(); err != nil {
			return Description{}, err
		}
		return Description{}, errors.New("ICE gathered no usable candidates")
	}
	d := Description{Ufrag: ufrag, Password: password, Candidates: make([]string, 0, len(candidates))}
	for _, candidate := range candidates {
		d.Candidates = append(d.Candidates, candidate.Marshal())
	}
	return d, nil
}

func (s *ICE) Connect(ctx context.Context, remote Description, controlling bool) error {
	if len(remote.Ufrag) < 4 || len(remote.Password) < 22 || len(remote.Candidates) == 0 || len(remote.Candidates) > 64 {
		return errors.New("invalid remote ICE description")
	}
	for _, raw := range remote.Candidates {
		if len(raw) > 2048 {
			return errors.New("ICE candidate too long")
		}
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			return errors.New("invalid remote ICE candidate")
		}
		if err = s.agent.AddRemoteCandidate(candidate); err != nil {
			return err
		}
	}
	var c *ice.Conn
	var err error
	if controlling {
		c, err = s.agent.Dial(ctx, remote.Ufrag, remote.Password)
	} else {
		c, err = s.agent.Accept(ctx, remote.Ufrag, remote.Password)
	}
	if err != nil {
		// Pion reports ErrCanceledByCaller for both cancellation and timeout.
		// Preserve the context cause for callers' retry/status handling.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("ICE connection failed: %w", err)
	}
	// Selection callbacks are asynchronous. Publish the actual selected path
	// before returning; quota enforcement must never briefly mistake TURN for
	// a direct connection.
	pair, err := s.agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		c.Close()
		return errors.New("ICE connected without a selected candidate pair")
	}
	s.relay.Store(pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay)
	s.mu.Lock()
	s.conn = c
	s.mu.Unlock()
	return nil
}

func (s *ICE) Read(p []byte) (int, error) {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c == nil {
		return 0, net.ErrClosed
	}
	n, err := c.Read(p)
	s.received.Add(uint64(n))
	return n, err
}

func (s *ICE) Write(p []byte) (int, error) {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c == nil {
		return 0, net.ErrClosed
	}
	n, err := c.Write(p)
	s.sent.Add(uint64(n))
	return n, err
}

func (s *ICE) Stats() Stats {
	return Stats{Relay: s.relay.Load(), Sent: s.sent.Load(), Received: s.received.Load()}
}
func (s *ICE) Close() error {
	var err error
	s.close.Do(func() { err = s.agent.Close(); s.doneOnce.Do(func() { close(s.done) }) })
	return err
}
func (s *ICE) Done() <-chan struct{} { return s.done }

func virtualAddress(ip net.IP) bool {
	v := ip.To4()
	return v != nil && v[0] == 100 && v[1] >= 96 && v[1] <= 127
}

func inPrefix(prefix netip.Prefix, ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	return ok && prefix.Contains(address.Unmap())
}

func (s *ICE) CandidateTypes() (string, string, error) {
	pair, err := s.agent.GetSelectedCandidatePair()
	if err != nil {
		return "", "", err
	}
	if pair == nil {
		return "", "", errors.New("ICE has no selected candidate pair")
	}
	return pair.Local.Type().String(), pair.Remote.Type().String(), nil
}
