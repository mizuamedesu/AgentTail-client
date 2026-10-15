// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/transport"
	"golang.zx2c4.com/wireguard/device"
)

// Resuming flows on both ends can cross two initial handshake initiations.
// Each response then replaces the state needed to consume the other response.
// For the first session on a new ICE link, prefer the smaller public key's
// pending initiation. WireGuard still authenticates every accepted message.
// The preference lasts at most one retry interval, and stops after WireGuard
// emits encrypted transport data with the freshly negotiated send key.
type initialHandshake struct {
	transport.Datagram
	preferred    bool
	mu           sync.Mutex
	pendingUntil time.Time
	established  bool
}

func (d *initialHandshake) Read(p []byte) (int, error) {
	for {
		n, err := d.Datagram.Read(p)
		if err != nil || n < 4 || binary.LittleEndian.Uint32(p[:4]) != device.MessageInitiationType {
			return n, err
		}
		d.mu.Lock()
		crossed := d.preferred && !d.established && time.Now().Before(d.pendingUntil)
		d.mu.Unlock()
		if !crossed {
			return n, nil
		}
	}
}

func (d *initialHandshake) Write(p []byte) (int, error) {
	if len(p) >= 4 {
		d.mu.Lock()
		switch binary.LittleEndian.Uint32(p[:4]) {
		case device.MessageInitiationType:
			if !d.established {
				d.pendingUntil = time.Now().Add(device.RekeyTimeout)
			}
		case device.MessageResponseType:
			d.pendingUntil = time.Time{}
		case device.MessageTransportType:
			d.established = true
		}
		d.mu.Unlock()
	}
	return d.Datagram.Write(p)
}
