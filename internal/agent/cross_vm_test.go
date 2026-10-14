package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mizuamedesu/AgentTail/internal/api"
	"github.com/mizuamedesu/AgentTail/internal/localstate"
	"golang.org/x/crypto/ssh"
)

type crossPeer struct {
	Label   string `json:"label"`
	ID      string `json:"key_id"`
	Address string `json:"address"`
	SSH     string `json:"ssh_public"`
}
type crossPhase struct {
	Name    string      `json:"name"`
	ID      string      `json:"key_id"`
	Grant   string      `json:"grant_id"`
	Public  string      `json:"public_key"`
	Private []byte      `json:"private_key"`
	Token   string      `json:"credential"`
	SSHSeed []byte      `json:"ssh_seed"`
	Address string      `json:"address"`
	Peers   []crossPeer `json:"peers"`
}
type crossConfig struct {
	Run     string       `json:"run_id"`
	Label   string       `json:"label"`
	Server  string       `json:"server"`
	Expires int64        `json:"expires_at"`
	Phases  []crossPhase `json:"phases"`
}
type crossProbe struct {
	Peer     string  `json:"peer"`
	Address  string  `json:"address"`
	Path     string  `json:"path"`
	PingMS   float64 `json:"ping_ms"`
	SSH      bool    `json:"authenticated_ssh"`
	Bytes    int     `json:"ssh_payload_bytes"`
	Elapsed  float64 `json:"completed_after_seconds"`
	Attempts int     `json:"probe_attempts"`
}
type crossFailure struct {
	Peer  string `json:"peer"`
	Error string `json:"error"`
}
type crossResult struct {
	Phase    string         `json:"phase"`
	Passed   bool           `json:"passed"`
	Probes   []crossProbe   `json:"outbound"`
	Inbound  []string       `json:"inbound_acknowledged"`
	Status   Status         `json:"final_status"`
	Failures []crossFailure `json:"failures,omitempty"`
	Duration float64        `json:"duration_seconds"`
}

// This deliberately uses native OS TUN/IP sockets and the deployed control
// service. It is opt-in; each job receives only its short-lived key grants.
func TestCrossVMCloudflareAcceptance(t *testing.T) {
	file := os.Getenv("AGENTTAIL_CROSS_VM_CONFIG")
	if file == "" {
		t.Skip("requires six concurrent hosted VMs and scoped fixtures")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("read CI fixture:", err)
	}
	var config crossConfig
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("invalid CI fixture")
	}
	clear(raw)
	if config.Server != "https://agenttail-api.mizuame.app" || config.Run == "" || len(config.Phases) != 2 || time.Now().Unix() >= config.Expires {
		t.Fatal("unexpected or expired CI fixture")
	}
	report := struct {
		Run     string        `json:"run_id"`
		Label   string        `json:"label"`
		OS      string        `json:"os"`
		Arch    string        `json:"arch"`
		Commit  string        `json:"commit"`
		Native  bool          `json:"native_tun"`
		Control string        `json:"control"`
		Scope   string        `json:"scope"`
		Results []crossResult `json:"phases"`
	}{config.Run, config.Label, runtime.GOOS, runtime.GOARCH, os.Getenv("GITHUB_SHA"), true, config.Server, "Independent GitHub-hosted VMs; real control, native TUN, WireGuard, ICE and Cloudflare TURN; pre-provisioned device credentials, not interactive login", nil}
	defer func() {
		path := os.Getenv("AGENTTAIL_CROSS_VM_REPORT")
		if path == "" {
			return
		}
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Error(err)
			return
		}
		// Only public metadata and measurements are exported; the unprivileged
		// artifact uploader must be able to read a report produced under sudo.
		if err = os.MkdirAll(filepath.Dir(path), 0755); err == nil {
			err = os.WriteFile(path, append(data, '\n'), 0644)
		}
		if err != nil {
			t.Error(err)
		}
	}()
	for i := range config.Phases {
		phase := &config.Phases[i]
		result := crossResult{Phase: phase.Name}
		passed := t.Run(phase.Name, func(t *testing.T) { crossRun(t, config, phase, &result) })
		result.Passed = passed
		report.Results = append(report.Results, result)
		clear(phase.Private)
		clear(phase.SSHSeed)
		phase.Token = ""
	}
}

func crossRun(t *testing.T, config crossConfig, phase *crossPhase, result *crossResult) {
	started := time.Now()
	defer func() { result.Duration = time.Since(started).Seconds() }()
	if len(phase.Peers) != 5 || len(phase.SSHSeed) != ed25519.SeedSize {
		t.Fatal("incomplete six-VM fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	client, err := api.New(config.Server, phase.Token, false)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewKey(Options{Client: client,
		Metadata:         localstate.Key{ID: phase.ID, Name: config.Label, Public: phase.Public, GrantID: phase.Grant, AutoUp: true},
		Credential:       localstate.KeyCredential{KeyID: phase.ID, Public: phase.Public, Private: phase.Private, Token: phase.Token},
		RelayOnlyForTest: phase.Name == "relay", ForceRelayForTest: phase.Name == "relay"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); key.Run(ctx) }()
	defer func() {
		result.Status = key.Status()
		_ = key.SetDesired(false)
		cancel()
		<-done
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := client.Do(cleanup, "POST", "/api/agent/logout", map[string]any{}, nil, ""); err != nil {
			t.Log("fixture grant cleanup:", err)
		}
	}()
	for key.Status().Interface == "" {
		select {
		case <-ctx.Done():
			t.Fatal("native interface did not become ready:", key.Status())
		case <-time.After(time.Second):
		}
	}
	if key.Status().Address != phase.Address {
		t.Fatal("unexpected virtual address")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(phase.Address, "2222"))
	if err != nil {
		t.Fatal("native SSH listener:", err)
	}
	defer listener.Close()
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(phase.SSHSeed))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	inbound := map[string]bool{}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, peer := range phase.Peers {
			if inbound[peer.Label] {
				result.Inbound = append(result.Inbound, peer.Label)
			}
		}
	}()
	sshConfig := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, public ssh.PublicKey) (*ssh.Permissions, error) {
		for _, peer := range phase.Peers {
			if meta.User() == peer.Label && base64.StdEncoding.EncodeToString(public.Marshal()) == peer.SSH {
				return &ssh.Permissions{Extensions: map[string]string{"peer": peer.Label}}, nil
			}
		}
		return nil, errors.New("unknown CI peer")
	}}
	sshConfig.AddHostKey(signer)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go crossServeSSH(connection, sshConfig, config.Run, config.Label, func(label string) { mu.Lock(); inbound[label] = true; mu.Unlock() })
		}
	}()
	// Probe every direction independently. A slow first peer must not prevent
	// the remaining healthy links from being measured before the deadline.
	probes := make([]crossProbe, len(phase.Peers))
	errorsByPeer := make([]error, len(phase.Peers))
	var probesDone sync.WaitGroup
	for index, peer := range phase.Peers {
		probesDone.Add(1)
		go func() {
			defer probesDone.Done()
			var last error = errors.New("ICE did not connect")
			attempts := 0
			for {
				status := key.Status()
				path := ""
				for _, p := range status.Peers {
					if p.ID == peer.ID && p.State == "connected" {
						path = p.Path
					}
				}
				if path != "" && (phase.Name != "relay" || path == "relay") {
					attempts++
					elapsed, err := nativePing(phase.Address, peer.Address)
					last = err
					if err == nil {
						count, err := crossDialSSH(ctx, phase.Address, peer, signer, config.Run, config.Label)
						last = err
						if err == nil {
							probes[index] = crossProbe{peer.Label, peer.Address, path, float64(elapsed.Microseconds()) / 1000, true, count, time.Since(started).Seconds(), attempts}
							t.Logf("%s -> %s: %s, ping %.3f ms, authenticated SSH %d bytes, completed after %.1f s (%d probes)", config.Label, peer.Label, path, probes[index].PingMS, count, probes[index].Elapsed, attempts)
							return
						}
					}
				}
				select {
				case <-ctx.Done():
					errorsByPeer[index] = last
					return
				case <-time.After(2 * time.Second):
				}
			}
		}()
	}
	probesDone.Wait()
	for index, peer := range phase.Peers {
		if err := errorsByPeer[index]; err != nil {
			result.Failures = append(result.Failures, crossFailure{peer.Label, err.Error()})
			t.Errorf("%s ping/SSH failed: %v", peer.Label, err)
		} else {
			result.Probes = append(result.Probes, probes[index])
		}
	}
	if t.Failed() {
		return
	}
	// Keep each VM alive until every remote VM acknowledges its successful
	// test toward this VM. No shared artifact or controller tunnels the data.
	for {
		mu.Lock()
		complete := len(inbound) == len(phase.Peers)
		mu.Unlock()
		if complete {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("not all remote VMs acknowledged successful SSH")
		case <-time.After(time.Second):
		}
	}
	time.Sleep(3 * time.Second)
}

func crossServeSSH(connection net.Conn, config *ssh.ServerConfig, run, label string, acknowledge func(string)) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for request := range channels {
		if request.ChannelType() != "session" {
			_ = request.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, messages, err := request.Accept()
		if err != nil {
			return
		}
		for message := range messages {
			var command struct{ Command string }
			if message.Type != "exec" || ssh.Unmarshal(message.Payload, &command) != nil || (command.Command != "probe:"+run && command.Command != "ack:"+run) {
				_ = message.Reply(false, nil)
				continue
			}
			_ = message.Reply(true, nil)
			if strings.HasPrefix(command.Command, "probe:") {
				_, err = io.WriteString(channel, run+":"+label+"\n"+strings.Repeat("AgentTail cross-VM payload\n", 4096))
			} else {
				acknowledge(server.Permissions.Extensions["peer"])
			}
			status := uint32(0)
			if err != nil {
				status = 1
			}
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			_ = channel.Close()
			break
		}
	}
}

func crossDialSSH(ctx context.Context, source string, peer crossPeer, signer ssh.Signer, run, label string) (int, error) {
	publicRaw, err := base64.StdEncoding.DecodeString(peer.SSH)
	if err != nil {
		return 0, err
	}
	public, err := ssh.ParsePublicKey(publicRaw)
	if err != nil {
		return 0, err
	}
	address := net.JoinHostPort(peer.Address, "2222")
	connection, err := (&net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return 0, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(25 * time.Second))
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, &ssh.ClientConfig{User: label, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(public), Timeout: 10 * time.Second})
	if err != nil {
		return 0, err
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return 0, err
	}
	output, err := session.Output("probe:" + run)
	_ = session.Close()
	if err != nil {
		return 0, err
	}
	expected := []byte(run + ":" + peer.Label + "\n" + strings.Repeat("AgentTail cross-VM payload\n", 4096))
	if !bytes.Equal(output, expected) {
		return 0, fmt.Errorf("unexpected remote identity or payload from %s", peer.Label)
	}
	ack, err := client.NewSession()
	if err != nil {
		return 0, err
	}
	defer ack.Close()
	if err := ack.Run("ack:" + run); err != nil {
		return 0, err
	}
	return len(output), nil
}
