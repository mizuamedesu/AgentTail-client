// SPDX-License-Identifier: GPL-3.0-or-later

package transport

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type counterDatagram struct{ writes atomic.Int64 }

func (d *counterDatagram) Read([]byte) (int, error)    { return 0, io.EOF }
func (d *counterDatagram) Write(p []byte) (int, error) { d.writes.Add(1); return len(p), nil }
func (d *counterDatagram) Close() error                { return nil }

func TestExpiredLeaseAndRelayBlockEveryDatagram(t *testing.T) {
	gate, relay := &LeaseGate{}, &LeaseGate{}
	gate.Renew(time.Now(), time.Minute)
	relay.Renew(time.Now().Add(-time.Minute), time.Minute)
	transport := &counterDatagram{}
	link := &Guarded{Datagram: transport, Lease: gate, Relay: relay}
	if _, err := link.Write([]byte("encrypted")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("expired relay transmitted")
	}
	link.Relay = nil // direct continues independently of relay allowance
	if _, err := link.Write([]byte("encrypted")); err != nil {
		t.Fatal(err)
	}
	gate.Stop()
	if _, err := link.Write([]byte("encrypted")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("revoked key transmitted")
	}
	if transport.writes.Load() != 1 {
		t.Fatal("unexpected underlying writes")
	}
	gate.until.Store(&validity{monotonic: time.Now().Add(time.Minute), wall: time.Now().Add(-time.Second).UnixNano()})
	if gate.Valid() {
		t.Fatal("machine sleep or a wall-clock deadline did not expire the lease")
	}
}
