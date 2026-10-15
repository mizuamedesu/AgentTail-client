// SPDX-License-Identifier: GPL-3.0-or-later

// Package agent maintains key-scoped control leases and the WireGuard/ICE data
// plane. It never loads account/admin sessions or an account vault key.
package agent

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/netdev"
	"github.com/mizuamedesu/AgentTail-client/internal/transport"
)

const SyncInterval = 20 * time.Second
const RequestTimeout = 5 * time.Second

type KeyInfo struct {
	VPNID    string `json:"vpn_id"`
	ID       string `json:"key_id"`
	Name     string `json:"name"`
	Public   string `json:"public_key"`
	Address  string `json:"virtual_ip"`
	CIDR     string `json:"ipv4_cidr,omitempty"`
	Instance string `json:"instance_id"`
}
type Signal struct {
	ID          string                `json:"signal_id"`
	Source      string                `json:"source_key_id"`
	Instance    string                `json:"source_instance"`
	Generation  string                `json:"generation"`
	Kind        string                `json:"kind"`
	Description transport.Description `json:"description"`
}
type Command struct {
	ID     string `json:"command_id"`
	Action string `json:"action"`
}
type Limits struct {
	MaxConnections int `json:"max_connections"`
	BytesPerSecond int `json:"bytes_per_second"`
	RelayDisabled  int `json:"relay_disabled"`
}
type configuration struct {
	Key            KeyInfo   `json:"key"`
	Instance       string    `json:"instance_id"`
	Killed         bool      `json:"killed"`
	Desired        string    `json:"desired_state"`
	Limits         Limits    `json:"limits"`
	Peers          []KeyInfo `json:"peers"`
	Signals        []Signal  `json:"signals"`
	Commands       []Command `json:"commands"`
	RelayAllowed   bool      `json:"relay_allowed"`
	ActiveTURN     []string  `json:"active_turn_credentials"`
	LeaseRemaining int       `json:"lease_remaining_seconds"`
}
type PeerStatus struct {
	ID       string `json:"key_id"`
	Name     string `json:"name"`
	Address  string `json:"virtual_ip"`
	State    string `json:"state"`
	Path     string `json:"path,omitempty"`
	Stage    string `json:"connection_stage,omitempty"`
	Problem  string `json:"last_error,omitempty"`
	Sent     uint64 `json:"wireguard_bytes_sent"`
	Received uint64 `json:"wireguard_bytes_received"`
}
type Status struct {
	ID          string       `json:"key_id"`
	Name        string       `json:"name"`
	Public      string       `json:"public_key"`
	Instance    string       `json:"instance_id"`
	State       string       `json:"state"`
	Desired     string       `json:"desired_state"`
	Interface   string       `json:"interface,omitempty"`
	NetworkMode string       `json:"network_mode"`
	SOCKS5      string       `json:"socks5,omitempty"`
	Address     string       `json:"virtual_ip,omitempty"`
	CIDR        string       `json:"ipv4_cidr,omitempty"`
	Authorized  bool         `json:"lease_valid"`
	LastSync    int64        `json:"last_sync_at,omitempty"`
	Problem     string       `json:"error,omitempty"`
	Peers       []PeerStatus `json:"peers"`
	Sent        uint64       `json:"wireguard_bytes_sent"`
	Received    uint64       `json:"wireguard_bytes_received"`
	Dropped     uint64       `json:"bandwidth_dropped_bytes"`
}

type Options struct {
	Client     *api.Client
	Metadata   localstate.Key
	Credential localstate.KeyCredential
	State      *localstate.State
	Factory    netdev.Factory
	// Test injection is available to Go integration tests, never a CLI option.
	STUN                  []transport.ICEServer
	LoopbackOnly          bool
	DisableEvents         bool
	RelayOnlyForTest      bool
	ForceRelayForTest     bool
	AttemptTimeoutForTest time.Duration
}

func (c configuration) validate(key localstate.Key, instance string) error {
	if c.Key.ID != key.ID || c.Key.Public != key.Public || c.Instance != instance || key.VPNID != "" && c.Key.VPNID != key.VPNID {
		return errors.New("server returned a different key scope")
	}
	address, err := netdev.Address(c.Key.Address)
	if err != nil {
		return err
	}
	cidr := c.Key.CIDR
	if cidr == "" {
		cidr = netdev.AddressPool.String()
	}
	network, err := netdev.Network(cidr)
	if err != nil || !netdev.HostInNetwork(network, address) {
		return errors.New("own address is outside the VPN IPv4 range")
	}
	if c.Desired != "up" && c.Desired != "down" {
		return errors.New("invalid desired state")
	}
	if c.Limits.MaxConnections < 1 || c.Limits.MaxConnections > 100 || c.Limits.BytesPerSecond < 1024 || c.Limits.BytesPerSecond > 125000000 {
		return errors.New("invalid account limits")
	}
	if len(c.Peers) > 100 || len(c.Signals) > 200 || len(c.Commands) > 100 {
		return errors.New("control response exceeds connection limits")
	}
	ids, publics, addresses := map[string]bool{key.ID: true}, map[string]bool{key.Public: true}, map[string]bool{c.Key.Address: true}
	for _, p := range c.Peers {
		if _, err := uuid.Parse(p.ID); err != nil {
			return errors.New("invalid peer ID")
		}
		if _, err := uuid.Parse(p.Instance); err != nil {
			return errors.New("invalid peer instance")
		}
		if _, err := cryptobox.Fingerprint(p.Public); err != nil {
			return err
		}
		peerAddress, err := netdev.Address(p.Address)
		if err != nil {
			return err
		}
		if !netdev.HostInNetwork(network, peerAddress) {
			return errors.New("peer address is outside the VPN IPv4 range")
		}
		if ids[p.ID] || publics[p.Public] || addresses[p.Address] {
			return errors.New("duplicate peer identity")
		}
		ids[p.ID], publics[p.Public], addresses[p.Address] = true, true, true
	}
	for _, command := range c.Commands {
		if _, err := uuid.Parse(command.ID); err != nil {
			return errors.New("invalid command ID")
		}
		if command.Action != "up" && command.Action != "down" && command.Action != "sync" {
			return fmt.Errorf("unsupported agent command")
		}
	}
	return nil
}
