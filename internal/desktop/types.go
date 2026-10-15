// SPDX-License-Identifier: GPL-3.0-or-later

// Package desktop defines the small, credential-free interface of the desktop
// VPN manager. The window never reads the privileged credential store.
package desktop

type VPN struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	VPNID     string `json:"vpn_id"`
	State     string `json:"state"`
	Desired   string `json:"desired"`
	Address   string `json:"address,omitempty"`
	Mode      string `json:"mode"`
	SOCKS5    string `json:"socks5,omitempty"`
	Problem   string `json:"problem,omitempty"`
	Peers     int    `json:"peers"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRead uint64 `json:"bytes_read"`
}

type Snapshot struct {
	Version string `json:"version"`
	Running bool   `json:"running"`
	VPNs    []VPN  `json:"vpns"`
}

type Action struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}
