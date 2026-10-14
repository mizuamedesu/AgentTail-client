// SPDX-License-Identifier: GPL-3.0-or-later

package transport

import (
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type validity struct {
	monotonic time.Time
	wall      int64
}

// LeaseGate is checked on every encrypted datagram. A failed control request
// never extends it. The wall deadline also expires leases across machine sleep,
// on systems whose monotonic clock pauses while suspended.
type LeaseGate struct{ until atomic.Pointer[validity] }

func (g *LeaseGate) Renew(start time.Time, ttl time.Duration) {
	if ttl <= 0 || ttl > time.Minute {
		g.Stop()
		return
	}
	end := start.Add(ttl)
	g.until.Store(&validity{monotonic: end, wall: end.UnixNano()})
}
func (g *LeaseGate) Stop() { g.until.Store(nil) }
func (g *LeaseGate) Valid() bool {
	u := g.until.Load()
	n := time.Now()
	return u != nil && n.Before(u.monotonic) && n.UnixNano() < u.wall
}

// Remaining is diagnostic; Valid is still checked for every datagram.
func (g *LeaseGate) Remaining() time.Duration {
	u := g.until.Load()
	if u == nil {
		return 0
	}
	n := time.Now()
	return max(0, min(u.monotonic.Sub(n), time.Duration(u.wall-n.UnixNano())))
}

// Budget is shared by every peer of one key, in both directions. UDP drops
// excess datagrams instead of accumulating an unbounded queue. TURN accounting
// includes provider overhead; these counters do not replace provider analytics.
type Budget struct {
	limiter atomic.Pointer[rate.Limiter]
	dropped atomic.Uint64
}

func (b *Budget) Set(bytesPerSecond int) {
	if bytesPerSecond < 1 {
		bytesPerSecond = 1
	}
	if current := b.limiter.Load(); current != nil {
		current.SetLimit(rate.Limit(bytesPerSecond))
	} else {
		// At most ten 1280-byte TUN packets of initial burst per key.
		b.limiter.Store(rate.NewLimiter(rate.Limit(bytesPerSecond), 16384))
	}
}
func (b *Budget) allow(n int) bool {
	l := b.limiter.Load()
	if l == nil || !l.AllowN(time.Now(), n) {
		b.dropped.Add(uint64(n))
		return false
	}
	return true
}
func (b *Budget) DroppedBytes() uint64 { return b.dropped.Load() }

type Guarded struct {
	Datagram
	Lease       *LeaseGate
	Relay       *LeaseGate // nil for an ICE session without TURN credentials
	Budget      *Budget
	PathAllowed func() bool
	closed      atomic.Bool
}

func (g *Guarded) permitted() bool {
	return !g.closed.Load() && g.Lease.Valid() && (g.Relay == nil || g.Relay.Valid()) && (g.PathAllowed == nil || g.PathAllowed())
}
func (g *Guarded) Read(p []byte) (int, error) {
	for {
		if !g.permitted() {
			return 0, net.ErrClosed
		}
		n, err := g.Datagram.Read(p)
		if !g.permitted() {
			return 0, net.ErrClosed
		}
		if err != nil || g.Budget == nil || g.Budget.allow(n) {
			return n, err
		}
	}
}
func (g *Guarded) Write(p []byte) (int, error) {
	if !g.permitted() {
		return 0, net.ErrClosed
	}
	if g.Budget != nil && !g.Budget.allow(len(p)) {
		return len(p), nil
	}
	return g.Datagram.Write(p)
}
func (g *Guarded) Close() error {
	g.closed.Store(true)
	return g.Datagram.Close()
}
