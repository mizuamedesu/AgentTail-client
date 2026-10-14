// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"encoding/json"
	"errors"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/spf13/cobra"
	"strings"
)

type profile struct {
	Salt string        `json:"salt"`
	KDF  cryptobox.KDF `json:"kdf"`
}
type vaultProfile struct {
	Wrapped  json.RawMessage `json:"wrapped_vault"`
	Recovery json.RawMessage `json:"recovery_wrapped_vault"`
	Version  int             `json:"version"`
	Lost     int             `json:"vault_lost"`
}

func parseBox(raw json.RawMessage) (cryptobox.Box, error) {
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		raw = []byte(encoded)
	}
	var box cryptobox.Box
	err := json.Unmarshal(raw, &box)
	return box, err
}
func (o *options) derive(client *api.Client, email, password string) (cryptobox.Derived, error) {
	var p profile
	if err := client.Do(o.ctx, "POST", "/api/kdf", map[string]string{"email": strings.ToLower(strings.TrimSpace(email))}, &p, ""); err != nil {
		return cryptobox.Derived{}, err
	}
	raw := []byte(password)
	defer clear(raw)
	return cryptobox.Derive(raw, p.Salt, p.KDF)
}
func (o *options) addAccount(root *cobra.Command, admin bool) {
	name := "account"
	if admin {
		name = "admin"
	}
	group := &cobra.Command{Use: name, Short: "Interactive account and vault management"}
	root.AddCommand(group)
	group.AddCommand(&cobra.Command{Use: "login", Short: "Sign in interactively using email and password", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return o.loginAccount(admin, false) }})
	group.AddCommand(&cobra.Command{Use: "logout", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		session, err := o.state.LoadSession(admin)
		if err != nil {
			return err
		}
		if session.Server != o.server {
			return errors.New("stored session belongs to a different server")
		}
		client, err := o.client(session.Token)
		if err != nil {
			return err
		}
		if err = client.Do(o.ctx, "POST", "/api/auth/sign-out", map[string]any{}, nil, ""); err != nil {
			var problem *api.Error
			if !errors.As(err, &problem) || problem.Code != "UNAUTHENTICATED" {
				return err
			}
		}
		scope := "account"
		if admin {
			scope = "admin"
		}
		if err = o.state.Store.Delete("session/" + scope); err != nil {
			return err
		}
		return o.print(map[string]any{"signed_out": true, "scope": scope})
	}})
	group.AddCommand(&cobra.Command{Use: "status", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		_, s, err := o.account(admin)
		if err != nil {
			return err
		}
		return o.print(map[string]string{"email": s.Email, "role": s.Role, "owner_id": s.OwnerID})
	}})
	if admin {
		return
	}
	group.AddCommand(&cobra.Command{Use: "register", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return o.loginAccount(false, true) }})
	group.AddCommand(&cobra.Command{Use: "change-password", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return o.changePassword() }})
	var replace bool
	recover := &cobra.Command{Use: "recover", Short: "Reset using an emailed token and a recovery key", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return o.recoverAccount(replace) }}
	recover.Flags().BoolVar(&replace, "replace-vault", false, "permanently revoke old keys and initialize a new vault")
	group.AddCommand(recover)
	group.AddCommand(&cobra.Command{Use: "request-reset", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		email, err := prompt("Email", false)
		if err != nil {
			return err
		}
		if err = o.requestPasswordReset(email); err != nil {
			return err
		}
		return o.print(map[string]string{"message": "If registered, this address will receive a reset link. Existing keys need the recovery key or an unlocked account client."})
	}})
}

func (o *options) requestPasswordReset(email string) error {
	client, err := o.client("")
	if err != nil {
		return err
	}
	return client.Do(o.ctx, "POST", "/api/auth/request-password-reset", map[string]string{"email": email, "redirectTo": o.webOrigin + "/reset"}, nil, "")
}

func (o *options) loginAccount(admin, register bool) error {
	email, err := prompt("Email", false)
	if err != nil {
		return err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	name := ""
	if register {
		name, err = prompt("Display name", false)
		if err != nil {
			return err
		}
	}
	password, err := prompt("Password (12+ UTF-8 bytes)", true)
	if err != nil {
		return err
	}
	client, err := o.client("")
	if err != nil {
		return err
	}
	derived, err := o.derive(client, email, password)
	password = ""
	if err != nil {
		return err
	}
	defer clear(derived.E)
	input := map[string]any{"email": email, "password": derived.Auth}
	endpoint := "/api/auth/sign-in/email"
	if register {
		endpoint = "/api/auth/sign-up/email"
		input["name"] = name
	}
	var response struct {
		Token string `json:"token"`
	}
	if err = client.Do(o.ctx, "POST", endpoint, input, &response, ""); err != nil {
		return err
	}
	if response.Token == "" {
		return o.print(map[string]string{"message": "Verify your email, then run agenttail account login."})
	}
	client.Token = response.Token
	path := "/api/account/me"
	if admin {
		path = "/api/admin/me"
	}
	var me struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err = client.Do(o.ctx, "GET", path, nil, &me, ""); err != nil {
		client.Do(o.ctx, "POST", "/api/auth/sign-out", map[string]any{}, nil, "")
		return err
	}
	v, recovery, err := o.unlock(client, me.ID, derived.E)
	if err != nil {
		client.Do(o.ctx, "POST", "/api/auth/sign-out", map[string]any{}, nil, "")
		return err
	}
	clear(v)
	scope := "account"
	if admin {
		scope = "admin"
	}
	if err = o.state.Store.Put("session/"+scope, localstate.Session{Token: response.Token, OwnerID: me.ID, Email: me.Email, Role: me.Role, Server: o.server}); err != nil {
		client.Do(o.ctx, "POST", "/api/auth/sign-out", map[string]any{}, nil, "")
		return err
	}
	if err = o.state.Update(o.saveOrigin); err != nil {
		client.Do(o.ctx, "POST", "/api/auth/sign-out", map[string]any{}, nil, "")
		o.state.Store.Delete("session/" + scope)
		return err
	}
	if recovery != "" {
		o.notice("Recovery key (save privately; shown once): %s", recovery)
	}
	return o.print(map[string]any{"email": me.Email, "role": me.Role, "session_scope": scope, "vault_key_saved": false})
}
func (o *options) unlock(client *api.Client, owner string, E []byte) ([]byte, string, error) {
	var p vaultProfile
	if err := client.Do(o.ctx, "GET", "/api/account/vault", nil, &p, ""); err != nil {
		return nil, "", err
	}
	if p.Lost != 0 {
		return nil, "", errors.New("vault is unrecoverable without a recovery key")
	}
	if len(p.Wrapped) > 0 && string(p.Wrapped) != "null" {
		box, err := parseBox(p.Wrapped)
		if err != nil {
			return nil, "", err
		}
		v, err := cryptobox.Open(E, box, cryptobox.VaultAAD(owner))
		return v, "", err
	}
	v, err := cryptobox.Random(32)
	if err != nil {
		return nil, "", err
	}
	raw, err := cryptobox.Random(32)
	if err != nil {
		clear(v)
		return nil, "", err
	}
	defer clear(raw)
	rk, err := cryptobox.RecoveryKey(raw, owner)
	if err != nil {
		clear(v)
		return nil, "", err
	}
	defer clear(rk)
	wrapper, err := cryptobox.Seal(E, v, cryptobox.VaultAAD(owner))
	if err != nil {
		clear(v)
		return nil, "", err
	}
	recovery, err := cryptobox.Seal(rk, v, cryptobox.RecoveryAAD(owner))
	if err != nil {
		clear(v)
		return nil, "", err
	}
	if err = client.Do(o.ctx, "PUT", "/api/account/vault", map[string]any{"version": p.Version, "wrapped_vault": wrapper, "recovery_wrapped_vault": recovery}, nil, ""); err != nil {
		clear(v)
		return nil, "", err
	}
	return v, cryptobox.Encode(raw), nil
}
func (o *options) unlockInteractive(client *api.Client, s localstate.Session) ([]byte, cryptobox.Derived, error) {
	password, err := prompt("Account password", true)
	if err != nil {
		return nil, cryptobox.Derived{}, err
	}
	derived, err := o.derive(client, s.Email, password)
	password = ""
	if err != nil {
		return nil, derived, err
	}
	v, recovery, err := o.unlock(client, s.OwnerID, derived.E)
	clear(derived.E)
	if recovery != "" {
		o.notice("Recovery key (save privately): %s", recovery)
	}
	return v, derived, err
}
func (o *options) changePassword() error {
	client, s, err := o.account(false)
	if err != nil {
		return err
	}
	v, current, err := o.unlockInteractive(client, s)
	if err != nil {
		return err
	}
	defer clear(v)
	password, err := newPassword()
	if err != nil {
		return err
	}
	next, err := o.derive(client, s.Email, password)
	password = ""
	if err != nil {
		return err
	}
	defer clear(next.E)
	var p vaultProfile
	if err = client.Do(o.ctx, "GET", "/api/account/vault", nil, &p, ""); err != nil {
		return err
	}
	wrapped, err := cryptobox.Seal(next.E, v, cryptobox.VaultAAD(s.OwnerID))
	if err != nil {
		return err
	}
	if err = client.Do(o.ctx, "POST", "/api/account/change-password", map[string]any{"currentPassword": current.Auth, "newPassword": next.Auth, "version": p.Version, "wrapped_vault": wrapped}, nil, ""); err != nil {
		return err
	}
	if err = o.state.Store.Delete("session/account"); err != nil {
		return err
	}
	return o.print(map[string]bool{"changed": true, "sign_in_required": true})
}
