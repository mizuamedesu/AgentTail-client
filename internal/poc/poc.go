// SPDX-License-Identifier: GPL-3.0-or-later

// Package poc exercises real WireGuard encryption and a complete IP/TCP stack.
// The unprivileged stack makes the same network test reproducible in CI.
package poc

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	netstack "github.com/mizuamedesu/AgentTail-client/internal/netstack"
	"github.com/mizuamedesu/AgentTail-client/internal/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/device"
)

type Config struct {
	Peers        [2][]transport.ICEServer
	RelayOnly    bool
	LoopbackOnly bool
	PingCount    int
}
type Report struct {
	Time            string             `json:"time"`
	Mode            string             `json:"mode"`
	LocalCandidate  string             `json:"local_candidate"`
	RemoteCandidate string             `json:"remote_candidate"`
	VirtualIPs      [2]string          `json:"virtual_ips"`
	PingMS          []float64          `json:"ping_ms"`
	SSH             string             `json:"ssh_result"`
	Stats           [2]transport.Stats `json:"transport"`
	Scope           string             `json:"scope"`
}

func Run(ctx context.Context, cfg Config) (Report, error) {
	report := Report{Time: time.Now().UTC().Format(time.RFC3339), VirtualIPs: [2]string{"100.96.0.1", "100.96.0.2"}, Scope: "two independent WireGuard devices and IP stacks on one host; not a cross-OS runtime test"}
	if cfg.PingCount <= 0 {
		cfg.PingCount = 3
	}
	var sessions [2]*transport.ICE
	for i := range sessions {
		s, err := transport.NewICE(transport.ICEOptions{Servers: cfg.Peers[i], RelayOnly: cfg.RelayOnly, LoopbackOnly: cfg.LoopbackOnly})
		if err != nil {
			return report, err
		}
		sessions[i] = s
		defer s.Close()
	}
	var descriptions [2]transport.Description
	errCh := make(chan error, 2)
	for i := range sessions {
		go func(i int) { var err error; descriptions[i], err = sessions[i].Gather(ctx); errCh <- err }(i)
	}
	for range sessions {
		if err := <-errCh; err != nil {
			return report, fmt.Errorf("gather: %w", err)
		}
	}
	for i := range sessions {
		go func(i int) { errCh <- sessions[i].Connect(ctx, descriptions[1-i], i == 0) }(i)
	}
	for range sessions {
		if err := <-errCh; err != nil {
			return report, err
		}
	}
	local, remote, err := sessions[0].CandidateTypes()
	if err != nil {
		return report, err
	}
	report.LocalCandidate, report.RemoteCandidate = local, remote
	report.Mode = "direct"
	if sessions[0].Stats().Relay {
		report.Mode = "relay"
	}
	if cfg.RelayOnly && (local != "relay" || remote != "relay") {
		return report, errors.New("relay-only test selected a non-relay candidate")
	}
	var private [2]*ecdh.PrivateKey
	var bindings [2]*transport.Bind
	var networks [2]*netstack.Net
	var devices [2]*device.Device
	for i := range private {
		private[i], err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return report, err
		}
	}
	for i := range devices {
		tun, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(report.VirtualIPs[i])}, nil, 1280)
		if err != nil {
			return report, err
		}
		networks[i] = network
		bindings[i] = transport.NewBind()
		devices[i] = device.NewDevice(tun, bindings[i], device.NewLogger(device.LogLevelError, "poc: "))
		defer devices[i].Close()
		config := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=peer-%d\nallowed_ip=%s/32\n", hex.EncodeToString(private[i].Bytes()), hex.EncodeToString(private[1-i].PublicKey().Bytes()), 1-i, report.VirtualIPs[1-i])
		if err := devices[i].IpcSet(config); err != nil {
			return report, err
		}
		if err := devices[i].Up(); err != nil {
			return report, err
		}
		if err := bindings[i].AddPeer(fmt.Sprintf("peer-%d", 1-i), sessions[i]); err != nil {
			return report, err
		}
	}
	for seq := 0; seq < cfg.PingCount; seq++ {
		elapsed, err := ping(ctx, networks[0], netip.MustParseAddr(report.VirtualIPs[1]), seq)
		if err != nil {
			return report, fmt.Errorf("WireGuard virtual-IP ping: %w", err)
		}
		report.PingMS = append(report.PingMS, float64(elapsed.Microseconds())/1000)
	}
	report.SSH, err = sshProbe(ctx, networks[0], networks[1], report.VirtualIPs[1])
	if err != nil {
		return report, fmt.Errorf("WireGuard virtual-IP SSH: %w", err)
	}
	for i := range sessions {
		report.Stats[i] = sessions[i].Stats()
	}
	return report, nil
}

func ping(ctx context.Context, network *netstack.Net, target netip.Addr, sequence int) (time.Duration, error) {
	socket, err := network.DialPingAddr(netip.Addr{}, target)
	if err != nil {
		return 0, err
	}
	defer socket.Close()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	socket.SetDeadline(deadline)
	data := make([]byte, 512)
	if _, err := rand.Read(data); err != nil {
		return 0, err
	}
	request := &icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: 42, Seq: sequence, Data: data}}
	raw, err := request.Marshal(nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err = socket.Write(raw); err != nil {
		return 0, err
	}
	response := make([]byte, 1500)
	n, err := socket.Read(response)
	if err != nil {
		return 0, err
	}
	m, err := icmp.ParseMessage(1, response[:n])
	if err != nil {
		return 0, err
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok || m.Type != ipv4.ICMPTypeEchoReply || echo.Seq != sequence || !bytes.Equal(data, echo.Data) {
		return 0, errors.New("invalid ICMP reply")
	}
	return time.Since(start), nil
}

func sshProbe(ctx context.Context, a, b *netstack.Net, target string) (string, error) {
	listener, err := b.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(target), 22))
	if err != nil {
		return "", err
	}
	defer listener.Close()
	deadline := time.Now().Add(15 * time.Second)
	if overall, ok := ctx.Deadline(); ok {
		deadline = overall // Virtual probe remains inside Run's total budget.
	}
	return checkSSH(ctx, a.DialContext, listener, target, deadline)
}

// CheckSSH verifies public-key authentication, host-key pinning and a command
// round trip. Both the netstack PoC and native TUN acceptance use this probe.
func CheckSSH(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), listener net.Listener, target string) (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	if overall, ok := ctx.Deadline(); ok {
		deadline = overall
	}
	return checkSSH(ctx, dial, listener, target, deadline)
}

func checkSSH(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), listener net.Listener, target string, deadline time.Time) (string, error) {
	clientDone := make(chan struct{})
	defer close(clientDone)
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	host, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		return "", err
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	clientKey, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		return "", err
	}
	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "poc" || !bytes.Equal(key.Marshal(), clientKey.PublicKey().Marshal()) {
			return nil, errors.New("unauthorized SSH key")
		}
		return &ssh.Permissions{}, nil
	}}
	serverConfig.AddHostKey(host)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(deadline)
		s, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		defer s.Close()
		go ssh.DiscardRequests(requests)
		for channel := range channels {
			if channel.ChannelType() != "session" {
				channel.Reject(ssh.UnknownChannelType, "session required")
				continue
			}
			ch, reqs, err := channel.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			for req := range reqs {
				var command struct{ Command string }
				if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != "agenttail-poc" {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				_, err = io.WriteString(ch, "AgentTail: authenticated SSH over encrypted virtual IP\n")
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				ch.Close()
				serverDone <- err
				// A channel close does not acknowledge delivery of its output.
				// Retain the TCP connection until the client has consumed it.
				timer := time.NewTimer(time.Until(deadline))
				defer timer.Stop()
				select {
				case <-clientDone:
				case <-ctx.Done():
				case <-timer.C:
				}
				return
			}
		}
	}()
	conn, err := dial(ctx, "tcp", target+":22")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(deadline)
	cc, chans, reqs, err := ssh.NewClientConn(conn, target+":22", &ssh.ClientConfig{User: "poc", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientKey)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 10 * time.Second})
	if err != nil {
		return "", fmt.Errorf("SSH client handshake: %w", err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("SSH session open: %w", err)
	}
	defer session.Close()
	output, err := session.Output("agenttail-poc")
	if err != nil {
		return "", fmt.Errorf("SSH command: %w", err)
	}
	if err := <-serverDone; err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
