// SPDX-License-Identifier: GPL-3.0-or-later

package netdev

import (
	"errors"
	"net/netip"
)

const DefaultSOCKS5 = "127.0.0.1:1080"

// Settings is public metadata. Userspace listeners are always loopback-only;
// destinations are limited separately to the current authorized peer set.
type Settings struct {
	Mode   string `json:"mode,omitempty"`
	SOCKS5 string `json:"socks5,omitempty"`
}

func (s Settings) Normalized() (Settings, error) {
	if s.Mode == "" {
		s.Mode = "native"
	}
	switch s.Mode {
	case "native":
		if s.SOCKS5 != "" {
			return s, errors.New("SOCKS5 requires userspace networking")
		}
	case "userspace":
		if s.SOCKS5 == "" {
			s.SOCKS5 = DefaultSOCKS5
		}
		addr, err := netip.ParseAddrPort(s.SOCKS5)
		if err != nil || !addr.Addr().IsLoopback() || addr.Addr().Zone() != "" || addr.Port() == 0 {
			return s, errors.New("SOCKS5 must be a literal loopback IP and port, for example 127.0.0.1:1080")
		}
		s.SOCKS5 = addr.String()
	default:
		return s, errors.New("network mode must be native or userspace")
	}
	return s, nil
}

func (s Settings) Factory() (Factory, error) {
	s, err := s.Normalized()
	if err != nil {
		return nil, err
	}
	if s.Mode == "userspace" {
		return func(id string, private []byte, address string) (Interface, error) {
			return newUserspace(id, private, address, s.SOCKS5)
		}, nil
	}
	return New, nil
}

// Proxy is implemented only by the userspace device; the native mode continues
// to route VPN peer addresses through the operating system.
type Proxy interface {
	SOCKS5Address() string
}
