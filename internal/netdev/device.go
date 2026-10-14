// SPDX-License-Identifier: GPL-3.0-or-later

// Package netdev owns a TUN device, WireGuard encryption and virtual-IP routes.
// It never changes DNS, forwarding, the default route, or application firewalls.
package netdev

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sync"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/transport"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const MTU = 1280

var AddressPool = netip.MustParsePrefix("100.96.0.0/11")

type Interface interface {
	Name() string
	SetPeer(id, public, address string) error
	RemovePeer(id string) error
	ConnectPeer(id string, link transport.Datagram) error
	DisconnectPeer(id string) error
	Close() error
}
type Factory func(keyID string, private []byte, address string) (Interface, error)

type routeManager interface {
	Add(netip.Addr) error
	Remove(netip.Addr) error
	Close() error
}
type peer struct {
	public  string
	address netip.Addr
}
type Device struct {
	mu         sync.Mutex
	name       string
	wg         *device.Device
	bind       *transport.Bind
	routes     routeManager
	peers      map[string]peer
	closed     bool
	registered bool
}

func Address(raw string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() || !(ip.IsPrivate() || HostInNetwork(AddressPool, ip)) {
		return netip.Addr{}, errors.New("virtual address is outside the allocated VPN range")
	}
	return ip, nil
}
func publicHex(raw string) (string, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != raw {
		return "", errors.New("invalid WireGuard public key")
	}
	return hex.EncodeToString(b), nil
}
func interfaceName(keyID string) string {
	sum := sha256.Sum256([]byte(keyID))
	return "at" + hex.EncodeToString(sum[:6])
}

func New(keyID string, private []byte, address string) (Interface, error) {
	ip, err := Address(address)
	if err != nil {
		return nil, err
	}
	t, routes, err := native(interfaceName(keyID), ip)
	if err != nil {
		return nil, err
	}
	return NewWithTUN(t, routes, private)
}

// NewWithTUN is also used by integration tests with a real userspace IP stack.
// Passing nil routes avoids touching host routing in those tests.
func NewWithTUN(t tun.Device, routes routeManager, private []byte) (Interface, error) {
	if len(private) != 32 {
		t.Close()
		if routes != nil {
			routes.Close()
		}
		return nil, errors.New("invalid WireGuard private key")
	}
	name, err := t.Name()
	if err != nil {
		t.Close()
		if routes != nil {
			routes.Close()
		}
		return nil, err
	}
	b := transport.NewBind()
	// The underlying library must not log its IPC configuration or secrets.
	wg := device.NewDevice(t, b, &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
	d := &Device{name: name, wg: wg, bind: b, routes: routes, peers: map[string]peer{}}
	if err = wg.IpcSet("private_key=" + hex.EncodeToString(private) + "\n"); err == nil {
		err = wg.Up()
	}
	if err != nil {
		d.Close()
		return nil, errors.New("WireGuard interface initialization failed")
	}
	registerVPNInterface(name, 1)
	d.registered = true
	return d, nil
}
func (d *Device) Name() string { return d.name }
func (d *Device) SetPeer(id, public, address string) error {
	if _, err := d.bind.ParseEndpoint(id); err != nil {
		return err
	}
	pub, err := publicHex(public)
	if err != nil {
		return err
	}
	ip, err := Address(address)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("interface closed")
	}
	if old, ok := d.peers[id]; ok {
		if old.public == pub && old.address == ip {
			return nil
		}
		return errors.New("peer identity cannot change in place")
	}
	for _, old := range d.peers {
		if old.public == pub || old.address == ip {
			return errors.New("duplicate peer public key or virtual address")
		}
	}
	if d.routes != nil {
		if err = d.routes.Add(ip); err != nil {
			return err
		}
	}
	if err = d.wg.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\npersistent_keepalive_interval=0\n", pub, id, ip)); err != nil {
		if d.routes != nil {
			d.routes.Remove(ip)
		}
		return errors.New("WireGuard peer configuration failed")
	}
	d.peers[id] = peer{pub, ip}
	return nil
}
func (d *Device) RemovePeer(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.peers[id]
	if !ok {
		return nil
	}
	// Remove the WireGuard peer before closing its transport and deleting routes.
	err := d.wg.IpcSet("public_key=" + p.public + "\nremove=true\n")
	d.bind.RemovePeer(id)
	if d.routes != nil {
		err = errors.Join(err, d.routes.Remove(p.address))
	}
	delete(d.peers, id)
	return err
}
func (d *Device) ConnectPeer(id string, link transport.Datagram) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.peers[id]; !ok || d.closed {
		link.Close()
		return errors.New("peer has no active authorization")
	}
	if err := d.bind.AddPeer(id, link); err != nil {
		return err
	}
	// ICE keeps the underlay allocation alive. Start WireGuard handshakes on
	// application traffic; simultaneous eager keepalives on both ends can race
	// handshake initiations and unnecessarily wait for the retry timer.
	return nil
}
func (d *Device) DisconnectPeer(id string) error { return d.bind.RemovePeer(id) }
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	d.wg.Close()
	if d.registered {
		registerVPNInterface(d.name, -1)
		d.registered = false
	}
	if d.routes != nil {
		return d.routes.Close()
	}
	return nil
}

func run(executable string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, executable, args...).Run(); err != nil {
		return fmt.Errorf("network configuration command %s failed: %w", executable, err)
	}
	return nil
}
