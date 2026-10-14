package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail/internal/api"
	"github.com/mizuamedesu/AgentTail/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail/internal/sshkeys"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func (o *options) addSSH(root *cobra.Command) {
	group := &cobra.Command{Use: "ssh", Short: "Install independent SSH keys for the current OS user"}
	root.AddCommand(group)
	group.AddCommand(&cobra.Command{Use: "list", Short: "List SSH keys in the account", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		client, _, err := o.account(false)
		if err != nil {
			return err
		}
		var rows []any
		if err = client.Pages(o.ctx, "/api/ssh-keys", &rows); err != nil {
			return err
		}
		return o.print(rows)
	}})
	var name string
	create := &cobra.Command{Use: "create", Short: "Create an independent encrypted Ed25519 SSH key", Args: cobra.NoArgs}
	create.Flags().StringVar(&name, "name", "", "SSH key name")
	required(create, "name")
	create.RunE = func(*cobra.Command, []string) error {
		client, session, err := o.account(false)
		if err != nil {
			return err
		}
		vault, _, err := o.unlockInteractive(client, session)
		if err != nil {
			return err
		}
		defer clear(vault)
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		defer clear(private)
		seed := private.Seed()
		defer clear(seed)
		key, err := ssh.NewPublicKey(pub)
		if err != nil {
			return err
		}
		public := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		id := uuid.NewString()
		box, err := cryptobox.Seal(vault, seed, "agenttail/v1/ssh-key/"+session.OwnerID+"/"+id+"/"+public)
		if err != nil {
			return err
		}
		var result any
		if err = client.Do(o.ctx, "POST", "/api/ssh-keys", map[string]any{"key_id": id, "name": name, "public_key": public, "encrypted_private_key": box}, &result, ""); err != nil {
			return err
		}
		return o.print(result)
	}
	group.AddCommand(create)
	o.addResourceEdits(group, "/api/ssh-keys", "revoke")
	var public string
	pub := &cobra.Command{Use: "install-public", Short: "Authorize an SSH public key on this computer (connection destination)", Args: cobra.NoArgs}
	pub.Flags().StringVar(&public, "public-key", "", "OpenSSH Ed25519 public key")
	required(pub, "public-key")
	pub.RunE = func(*cobra.Command, []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path, err := sshkeys.InstallPublicCurrent(home, public)
		if err != nil {
			return err
		}
		return o.print(map[string]any{"role": "ssh-server", "authorized_keys": path, "public_key": public, "note": "Use the SSH login account that ran this command. The SSH server must allow public-key authentication."})
	}
	group.AddCommand(pub)
	var selector, expected string
	priv := &cobra.Command{Use: "install-private", Short: "Receive one approved SSH private key on this computer (connection origin)", Args: cobra.NoArgs}
	priv.Flags().StringVar(&selector, "key", "", "SSH key name or ID")
	priv.Flags().StringVar(&expected, "public-key", "", "optional expected OpenSSH public key")
	required(priv, "key")
	priv.RunE = func(*cobra.Command, []string) error { return o.installSSHPrivate(selector, expected) }
	group.AddCommand(priv)
}

func (o *options) installSSHPrivate(selector, expected string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return o.receiveSSHPrivate(home, selector, expected)
}

func (o *options) receiveSSHPrivate(home, selector, expected string) error {
	if expected != "" {
		if _, err := sshkeys.Public(expected); err != nil {
			return err
		}
	}
	ephemeral, err := cryptobox.NewEphemeral()
	if err != nil {
		return err
	}
	client, err := o.client("")
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	label := runtime.GOOS + " / " + host
	if len(label) > 96 {
		label = label[:96]
	}
	var device struct {
		ID       string `json:"request_id"`
		Secret   string `json:"device_secret"`
		Code     string `json:"user_code"`
		URI      string `json:"verification_uri"`
		Interval int    `json:"interval"`
		Expires  int    `json:"expires_in"`
	}
	request := map[string]any{"key": selector, "ephemeral_public_key": ephemeral.Public, "cli_label": label}
	if expected != "" {
		request["expected_public_key"] = expected
	}
	if err = client.Do(o.ctx, "POST", "/api/ssh-device/start", request, &device, ""); err != nil {
		return err
	}
	if device.Interval < 5 || device.Interval > 30 || device.Expires < 1 || device.Expires > 300 {
		return errors.New("invalid SSH authorization limits")
	}
	fp, err := cryptobox.RecipientFingerprint(ephemeral.Public, device.ID)
	if err != nil {
		return err
	}
	link, err := o.approvalURL(device.URI, device.Code, fp, "/ssh-device")
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Duration(device.Expires) * time.Second)
	if o.json {
		o.print(map[string]any{"event": "ssh_authorization", "verification_uri": link, "user_code": device.Code, "recipient_fingerprint": fp, "expires_in": device.Expires})
	} else {
		if err := o.promptAuthorization("SSH private-key installation", link, device.Code, fp, deadline); err != nil {
			return err
		}
	}
	interval := time.Duration(device.Interval) * time.Second
	for time.Now().Before(deadline) {
		timer := time.NewTimer(interval)
		select {
		case <-o.ctx.Done():
			timer.Stop()
			return o.ctx.Err()
		case <-timer.C:
		}
		var result struct {
			ID       string             `json:"key_id"`
			Public   string             `json:"public_key"`
			Transfer cryptobox.Transfer `json:"encrypted_transfer"`
		}
		err = client.Do(o.ctx, "POST", "/api/ssh-device/poll", map[string]string{"request_id": device.ID, "device_secret": device.Secret}, &result, "")
		if err != nil {
			var p *api.Error
			if errors.As(err, &p) && (p.Code == "AUTHORIZATION_PENDING" || p.Code == "SLOW_DOWN") {
				if p.RetryAfter > 0 {
					interval = p.RetryAfter
				}
				continue
			}
			return err
		}
		if expected != "" && result.Public != expected {
			return errors.New("SSH public key changed during approval")
		}
		seed, err := cryptobox.OpenTransfer(ephemeral, device.ID, "ssh/"+result.ID, result.Transfer)
		if err != nil {
			return err
		}
		defer clear(seed)
		path, err := sshkeys.InstallPrivate(home, result.ID, result.Public, seed)
		if err != nil {
			return err
		}
		return o.print(map[string]any{"role": "ssh-client", "identity_file": path, "public_key": result.Public, "usage": "ssh -i <identity_file> <user>@<host>", "note": "This is an OpenSSH private key protected by OS file permissions. It is not passphrase-encrypted."})
	}
	return &api.Error{Code: "EXPIRED_TOKEN", Message: "SSH approval expired; run the installation command again"}
}
