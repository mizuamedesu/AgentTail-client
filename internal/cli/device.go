// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"errors"
	"github.com/mizuamedesu/AgentTail-client/internal/agent"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/spf13/cobra"
	"os"
	"runtime"
	"strings"
	"time"
)

func (o *options) addDevice(root *cobra.Command) {
	var vpn, machine string
	var connect bool
	login := &cobra.Command{Use: "join", Short: "Join a named VPN with a new device identity", Args: cobra.NoArgs}
	login.Flags().StringVar(&vpn, "name", "", "VPN name or ID")
	login.Flags().StringVar(&machine, "device-name", "", "device name (defaults to hostname)")
	login.Flags().BoolVar(&connect, "up", true, "connect after approval")
	required(login, "name")
	login.RunE = func(*cobra.Command, []string) error { return o.loginDevice(vpn, machine, connect) }
	var group *cobra.Command
	for _, cmd := range root.Commands() {
		if cmd.Name() == "vpn" {
			group = cmd
		}
	}
	group.AddCommand(login)
	var logoutName string
	logout := &cobra.Command{Use: "leave", Short: "Remove this device from a VPN", Args: cobra.NoArgs}
	logout.Flags().StringVar(&logoutName, "name", "", "VPN name or ID")
	required(logout, "name")
	logout.RunE = func(*cobra.Command, []string) error {
		key, err := o.config.Find(logoutName)
		if err != nil {
			return err
		}
		credential, err := o.state.LoadKey(key)
		if err != nil {
			return err
		}
		defer clear(credential.Private)
		if o.config.Server != o.server {
			return &api.Error{Code: "FORBIDDEN", Message: "key belongs to a different server"}
		}
		// Keep the credential when remote revocation cannot be confirmed.
		if err = o.stopDevice(key); err != nil {
			return err
		}
		client, err := o.client(credential.Token)
		if err != nil {
			return err
		}
		err = client.Do(o.ctx, "POST", "/api/agent/logout", map[string]any{}, nil, "")
		var p *api.Error
		if err != nil && !(errors.As(err, &p) && p.Status == 401 && p.Code == "UNAUTHENTICATED") {
			return err
		}
		if err = o.forgetDevice(key); err != nil {
			return err
		}
		return o.print(map[string]any{"key_id": key.ID, "revoked": true})
	}
	group.AddCommand(logout)
}

func (o *options) stopDevice(key localstate.Key) error {
	var problem *api.Error
	if err := agent.LocalRequest(o.ctx, o.state.Store.Dir, key.ID, "down", nil); err != nil && !(errors.As(err, &problem) && problem.Code == "AGENT_OFFLINE") {
		return err
	}
	return o.state.Update(func(c *localstate.Config) error {
		for i := range c.Keys {
			if c.Keys[i].ID == key.ID {
				if c.Server != o.server || c.Keys[i].GrantID != key.GrantID || c.Keys[i].Public != key.Public {
					return errors.New("local VPN registration changed; retry the command")
				}
				c.Keys[i].AutoUp = false
			}
		}
		return nil
	})
}

func (o *options) forgetDevice(key localstate.Key) error {
	// Remove the reference before its secret, so a restarted agent never loads
	// a configuration that points at a credential we have already deleted.
	if err := o.state.Update(func(c *localstate.Config) error {
		keys := make([]localstate.Key, 0, len(c.Keys))
		for _, k := range c.Keys {
			if k.ID == key.ID {
				if c.Server != o.server || k.GrantID != key.GrantID || k.Public != key.Public {
					return errors.New("local VPN registration changed; retry the command")
				}
				continue
			}
			keys = append(keys, k)
		}
		c.Keys = keys
		return nil
	}); err != nil {
		return err
	}
	if err := o.state.Store.Delete("key/" + key.ID); err != nil {
		return err
	}
	var err error
	o.config, err = o.state.Read()
	return err
}

func deviceAuthorized(ctx context.Context, client *api.Client, key localstate.Key) (bool, error) {
	var identity struct {
		KeyID   string `json:"key_id"`
		VPNID   string `json:"vpn_id"`
		GrantID string `json:"grant_id"`
		Public  string `json:"public_key"`
		Expires int64  `json:"expires_at"`
	}
	if err := client.Do(ctx, "GET", "/api/agent/identity", nil, &identity, ""); err != nil {
		var problem *api.Error
		if errors.As(err, &problem) && problem.Status == 401 && problem.Code == "UNAUTHENTICATED" {
			return false, nil
		}
		// An outage, an older server, a permission error or an invalid response
		// is not proof of revocation. Preserve the local registration.
		return false, err
	}
	if identity.KeyID != key.ID || identity.VPNID != key.VPNID || identity.GrantID != key.GrantID || identity.Public != key.Public || identity.Expires <= 0 {
		return false, &api.Error{Code: "FORBIDDEN", Message: "server identity did not match the stored VPN registration"}
	}
	return true, nil
}

func (o *options) prepareVPNJoin(vpn string) (*localstate.Key, error) {
	if o.config.Server != "" && o.config.Server != o.server && len(o.config.Keys) > 0 {
		return nil, errors.New("existing local keys belong to a different server")
	}
	for _, key := range o.config.Keys {
		if key.Name != vpn && key.VPNID != vpn {
			continue
		}
		credential, err := o.state.LoadKey(key)
		if err != nil {
			return nil, err
		}
		defer clear(credential.Private)
		client, err := o.client(credential.Token)
		if err != nil {
			return nil, err
		}
		authorized, err := deviceAuthorized(o.ctx, client, key)
		if err != nil {
			return nil, err
		}
		if authorized {
			return &key, nil
		}
		if err = o.stopDevice(key); err != nil {
			return nil, err
		}
		if err = o.forgetDevice(key); err != nil {
			return nil, err
		}
		o.notice("The previous VPN registration is no longer valid. Starting a new approval request.")
		break
	}
	return nil, nil
}

func (o *options) loginDevice(vpn, machine string, connect bool) error {
	if vpn == "" {
		return errors.New("specify --name with a VPN name or ID")
	}
	if machine == "" {
		machine, _ = os.Hostname()
	}
	if machine == "" {
		machine = runtime.GOOS
	}
	joined, err := o.prepareVPNJoin(vpn)
	if err != nil {
		return err
	}
	if joined != nil {
		if connect {
			return o.requestNetwork("up", joined.ID, joined.Name)
		}
		return o.print(map[string]any{"already_joined": true, "name": joined.Name, "vpn_id": joined.VPNID, "key_id": joined.ID, "public_key": joined.Public})
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
	input := map[string]any{"ephemeral_public_key": ephemeral.Public, "cli_label": label, "vpn": vpn, "name": machine}
	var device struct {
		ID       string `json:"request_id"`
		Secret   string `json:"device_secret"`
		Code     string `json:"user_code"`
		URI      string `json:"verification_uri"`
		Interval int    `json:"interval"`
		Expires  int    `json:"expires_in"`
	}
	if err = client.Do(o.ctx, "POST", "/api/device/start", input, &device, ""); err != nil {
		return err
	}
	if device.Interval < 5 || device.Interval > 30 || device.Expires < 1 || device.Expires > 300 {
		return errors.New("invalid device authorization limits")
	}
	recipientFingerprint, err := cryptobox.RecipientFingerprint(ephemeral.Public, device.ID)
	if err != nil {
		return err
	}
	approvalURL, err := o.deviceApprovalURL(device.URI, device.Code, recipientFingerprint)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Duration(device.Expires) * time.Second)
	if o.json {
		o.print(map[string]any{"event": "device_authorization", "user_code": device.Code, "verification_uri": approvalURL, "recipient_fingerprint": recipientFingerprint, "expires_in": device.Expires})
	} else {
		if err := o.promptAuthorization("VPN device", approvalURL, device.Code, recipientFingerprint, deadline); err != nil {
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
		var grant struct {
			KeyID    string             `json:"key_id"`
			Name     string             `json:"name"`
			VPNID    string             `json:"vpn_id"`
			VPNName  string             `json:"vpn_name"`
			Public   string             `json:"public_key"`
			GrantID  string             `json:"grant_id"`
			Token    string             `json:"credential"`
			Expires  int64              `json:"expires_at"`
			Transfer cryptobox.Transfer `json:"encrypted_transfer"`
		}
		err = client.Do(o.ctx, "POST", "/api/device/poll", map[string]string{"request_id": device.ID, "device_secret": device.Secret}, &grant, "")
		if err != nil {
			var problem *api.Error
			if errors.As(err, &problem) && (problem.Code == "AUTHORIZATION_PENDING" || problem.Code == "SLOW_DOWN") {
				if problem.RetryAfter > 0 {
					interval = problem.RetryAfter
				} else if problem.Code == "SLOW_DOWN" {
					interval += 5 * time.Second
				}
				continue
			}
			return err
		}
		// Poll consumes the transfer exactly once. If decrypt/validation/local
		// persistence fails, release its already-issued grant so another device
		// login is not blocked for the grant's full lifetime.
		accepted := false
		if strings.HasPrefix(grant.Token, "atk_") {
			defer func() {
				if accepted {
					return
				}
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(o.ctx), 5*time.Second)
				defer cancel()
				if revoke, e := o.client(grant.Token); e == nil {
					_ = revoke.Do(cleanup, "POST", "/api/agent/logout", map[string]any{}, nil, "")
				}
			}()
		}
		private, err := cryptobox.OpenTransfer(ephemeral, device.ID, grant.KeyID, grant.Transfer)
		if err != nil {
			return err
		}
		defer clear(private)
		public, err := cryptobox.PublicFromPrivate(private)
		if err != nil || public != grant.Public || (grant.VPNID != vpn && grant.VPNName != vpn) || !strings.HasPrefix(grant.Token, "atk_") {
			return errors.New("approved private key or credential did not match its scope")
		}
		credential := localstate.KeyCredential{KeyID: grant.KeyID, Public: public, Private: private, Token: grant.Token, Expires: grant.Expires}
		if err = o.state.Store.Put("key/"+grant.KeyID, credential); err != nil {
			return err
		}
		key := localstate.Key{ID: grant.KeyID, Name: grant.VPNName, VPNID: grant.VPNID, Public: public, GrantID: grant.GrantID, Expires: grant.Expires}
		err = o.state.Update(func(c *localstate.Config) error {
			if err := o.saveOrigin(c); err != nil {
				return err
			}
			for _, existing := range c.Keys {
				if existing.ID == key.ID || existing.VPNID == key.VPNID {
					return errors.New("local key was authorized concurrently")
				}
			}
			c.Keys = append(c.Keys, key)
			return nil
		})
		if err != nil {
			o.state.Store.Delete("key/" + grant.KeyID)
			return err
		}
		accepted = true
		fp, _ := publicFingerprint(public)
		if err = o.print(map[string]any{"name": grant.VPNName, "vpn_id": grant.VPNID, "device_name": grant.Name, "key_id": grant.KeyID, "public_key": public, "fingerprint": fp, "expires_at": grant.Expires, "scope": "vpn-device"}); err != nil {
			return err
		}
		if connect {
			return o.requestNetwork("up", grant.KeyID, grant.VPNName)
		}
		return nil
	}
	return &api.Error{Code: "EXPIRED_TOKEN", Message: "device code expired; run agenttail vpn join again"}
}
