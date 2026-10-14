// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"encoding/json"
	"errors"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"strings"
)

func (o *options) recoverAccount(replace bool) error {
	token, err := prompt("Reset token or email reset link", true)
	if err != nil {
		return err
	}
	token, err = o.resetToken(token)
	if err != nil {
		return err
	}
	client, err := o.client("")
	if err != nil {
		return err
	}
	var profile struct {
		Owner    string          `json:"owner_id"`
		Email    string          `json:"email"`
		Salt     string          `json:"salt"`
		KDF      cryptobox.KDF   `json:"kdf"`
		Recovery json.RawMessage `json:"recovery_wrapped_vault"`
		Version  int             `json:"version"`
	}
	if err = client.Do(o.ctx, "POST", "/api/recovery/inspect", map[string]string{"token": token}, &profile, ""); err != nil {
		return err
	}
	o.notice("Resetting %s. Existing key-only devices cannot recover the account vault.", profile.Email)
	var vault []byte
	newRecovery := ""
	if replace {
		yes, err := prompt("All existing private keys will be lost and all devices revoked. Type DELETE", false)
		if err != nil {
			return err
		}
		if yes != "DELETE" {
			return errors.New("vault replacement cancelled")
		}
		vault, err = cryptobox.Random(32)
		if err != nil {
			return err
		}
	} else {
		code, err := prompt("Recovery key", true)
		if err != nil {
			return err
		}
		raw, err := cryptobox.Decode(strings.TrimSpace(code), 32)
		code = ""
		if err != nil {
			return err
		}
		defer clear(raw)
		rk, err := cryptobox.RecoveryKey(raw, profile.Owner)
		if err != nil {
			return err
		}
		defer clear(rk)
		box, err := parseBox(profile.Recovery)
		if err != nil {
			return errors.New("this account has no valid recovery wrapper")
		}
		vault, err = cryptobox.Open(rk, box, cryptobox.RecoveryAAD(profile.Owner))
		if err != nil {
			return err
		}
	}
	defer clear(vault)
	password, err := newPassword()
	if err != nil {
		return err
	}
	rawPassword := []byte(password)
	derived, err := cryptobox.Derive(rawPassword, profile.Salt, profile.KDF)
	clear(rawPassword)
	password = ""
	if err != nil {
		return err
	}
	defer clear(derived.E)
	wrapped, err := cryptobox.Seal(derived.E, vault, cryptobox.VaultAAD(profile.Owner))
	if err != nil {
		return err
	}
	mode := "preserve"
	if replace {
		mode = "replace"
	}
	input := map[string]any{"token": token, "newPassword": derived.Auth, "version": profile.Version, "mode": mode, "wrapped_vault": wrapped, "acknowledge_key_loss": replace}
	if replace {
		raw, err := cryptobox.Random(32)
		if err != nil {
			return err
		}
		defer clear(raw)
		rk, err := cryptobox.RecoveryKey(raw, profile.Owner)
		if err != nil {
			return err
		}
		defer clear(rk)
		box, err := cryptobox.Seal(rk, vault, cryptobox.RecoveryAAD(profile.Owner))
		if err != nil {
			return err
		}
		input["recovery_wrapped_vault"] = box
		newRecovery = cryptobox.Encode(raw)
	}
	var result any
	if err = client.Do(o.ctx, "POST", "/api/recovery/complete", input, &result, ""); err != nil {
		return err
	}
	for _, admin := range []bool{false, true} {
		session, err := o.state.LoadSession(admin)
		if err == nil && session.OwnerID == profile.Owner {
			scope := "account"
			if admin {
				scope = "admin"
			}
			o.state.Store.Delete("session/" + scope)
		}
	}
	if newRecovery != "" {
		o.notice("New recovery key (save privately): %s", newRecovery)
	}
	return o.print(result)
}
