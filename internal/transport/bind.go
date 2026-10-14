package transport

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

// Datagram is an ICE connection or another datagram-preserving transport.
type Datagram interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}
type endpoint string

func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) DstToString() string { return string(e) }
func (e endpoint) DstToBytes() []byte  { return []byte(e) }
func (e endpoint) DstIP() netip.Addr   { return netip.IPv4Unspecified() }
func (e endpoint) SrcIP() netip.Addr   { return netip.IPv4Unspecified() }

var validEndpoint = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

type packet struct {
	data []byte
	peer endpoint
	link *link
}
type link struct {
	transport Datagram
	write     sync.Mutex
}
type generation struct {
	packets chan packet
	done    chan struct{}
}

// Bind implements WireGuard's datagram interface with one authenticated ICE
// connection per peer. The bounded receive queue drops excess UDP traffic.
type Bind struct {
	mu      sync.RWMutex
	current *generation
	peers   map[endpoint]*link
	dropped atomic.Uint64
}

var _ conn.Bind = (*Bind)(nil)

func NewBind() *Bind { return &Bind{peers: make(map[endpoint]*link)} }
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current != nil {
		return nil, 0, errors.New("bind already open")
	}
	g := &generation{packets: make(chan packet, 256), done: make(chan struct{})}
	b.current = g
	return []conn.ReceiveFunc{func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			select {
			case <-g.done:
				return 0, net.ErrClosed
			case p := <-g.packets:
				b.mu.RLock()
				active := b.peers[p.peer] == p.link
				b.mu.RUnlock()
				if !active {
					continue
				}
				if len(bufs) == 0 || len(sizes) == 0 || len(eps) == 0 {
					return 0, io.ErrShortBuffer
				}
				if len(p.data) > len(bufs[0]) {
					b.dropped.Add(1)
					continue
				}
				sizes[0] = copy(bufs[0], p.data)
				eps[0] = p.peer
				return 1, nil
			}
		}
	}}, port, nil
}

func (b *Bind) AddPeer(id string, transport Datagram) error {
	if !validEndpoint.MatchString(id) {
		return errors.New("invalid peer endpoint")
	}
	b.mu.Lock()
	g := b.current
	if g == nil {
		b.mu.Unlock()
		return net.ErrClosed
	}
	ep := endpoint(id)
	previous := b.peers[ep]
	l := &link{transport: transport}
	b.peers[ep] = l
	b.mu.Unlock()
	if previous != nil {
		previous.transport.Close()
	}
	go func() {
		defer func() {
			b.mu.Lock()
			if b.peers[ep] == l {
				delete(b.peers, ep)
			}
			b.mu.Unlock()
			transport.Close()
		}()
		buf := make([]byte, 65535)
		for {
			n, err := transport.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			p := packet{data: append([]byte(nil), buf[:n]...), peer: ep, link: l}
			select {
			case <-g.done:
				return
			case g.packets <- p:
			default:
				b.dropped.Add(1)
			}
		}
	}()
	return nil
}

func (b *Bind) RemovePeer(id string) error {
	b.mu.Lock()
	l := b.peers[endpoint(id)]
	delete(b.peers, endpoint(id))
	b.mu.Unlock()
	if l != nil {
		return l.transport.Close()
	}
	return nil
}

func (b *Bind) Close() error {
	b.mu.Lock()
	if b.current == nil {
		b.mu.Unlock()
		return nil
	}
	close(b.current.done)
	b.current = nil
	peers := b.peers
	b.peers = make(map[endpoint]*link)
	b.mu.Unlock()
	for _, l := range peers {
		l.transport.Close()
	}
	return nil
}

func (b *Bind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("socket marks unsupported for ICE bind")
	}
	return nil
}
func (b *Bind) BatchSize() int { return 1 }
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if !validEndpoint.MatchString(s) {
		return nil, errors.New("invalid peer endpoint")
	}
	return endpoint(s), nil
}
func (b *Bind) Dropped() uint64 { return b.dropped.Load() }
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.RLock()
	l := b.peers[endpoint(ep.DstToString())]
	b.mu.RUnlock()
	if l == nil {
		return net.ErrClosed
	}
	l.write.Lock()
	defer l.write.Unlock()
	for _, buf := range bufs {
		n, err := l.transport.Write(buf)
		if err != nil {
			return err
		}
		if n != len(buf) {
			return io.ErrShortWrite
		}
	}
	return nil
}
