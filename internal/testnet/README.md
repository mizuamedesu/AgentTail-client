# Test IP stack

`tun.go` is the MIT-licensed WireGuard Go netstack adapter from
`golang.zx2c4.com/wireguard@v0.0.0-20260522210424-ecfc5a8d5446`, with local fixes:
`PingConn.ReadFrom` registers its waiter, attempts a read, and waits only after
`ErrWouldBlock`. The upstream implementation waits before its first read, losing
the readiness notification when a fast ICMP reply is already queued. This caused
false timeouts on ARM macOS despite the reply traversing WireGuard and TURN.

Shutdown uses a separate done channel because removing the notification handler
does not join callbacks already in flight. Closing the packet channel could race
with a sender and panic. Read and cancelled notifications release their views.
The shutdown regression test closes the device during an active notification.

The output queue is bounded and does not wait for a TUN reader while a network
stack callback holds protocol locks. A stalled reader must not block ICMP or TCP
packet processing. Shutdown serializes with callbacks and releases queued views.
The queue regression test writes a packet before starting the TUN reader.

Keep the rest of the adapter identical to the pinned upstream version. The ICMP
regression test queues a reply before calling Read. The native `agenttail` binary uses
OS TUN/IP, not this adapter; this copy is for integration tests and `turn-poc`.
The complete upstream license is in `LICENSE`.

Source: https://git.zx2c4.com/wireguard-go/tree/tun/netstack/tun.go?id=ecfc5a8d5446
