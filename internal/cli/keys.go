// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"strings"

	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/cryptobox"
	"github.com/spf13/cobra"
)

func (o *options) addKeys(root *cobra.Command) {
	group := &cobra.Command{Use: "vpn", Short: "Manage named VPNs and this computer's membership"}
	root.AddCommand(group)
	group.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		client, _, err := o.account(false)
		if err != nil {
			return err
		}
		var items []any
		if err = client.Pages(o.ctx, "/api/vpns", &items); err != nil {
			return err
		}
		return o.print(items)
	}})
	var name, cidr string
	create := &cobra.Command{Use: "create", Short: "Create a named VPN", Args: cobra.NoArgs}
	create.Flags().StringVar(&name, "name", "", "VPN name")
	create.Flags().StringVar(&cidr, "cidr", "", "private IPv4 range (automatically selected when omitted)")
	required(create, "name")
	create.RunE = func(*cobra.Command, []string) error {
		client, _, err := o.account(false)
		if err != nil {
			return err
		}
		var result any
		input := map[string]any{"name": name}
		if cidr != "" {
			input["ipv4_cidr"] = cidr
		}
		if err = client.Do(o.ctx, "POST", "/api/vpns", input, &result, ""); err != nil {
			return err
		}
		return o.print(result)
	}
	group.AddCommand(create)
	o.addResourceEdits(group, "/api/vpns", "delete")
	var rangeID, rangeCIDR string
	var rangeVersion int
	setRange := &cobra.Command{Use: "set-range", Short: "Change a VPN's private IPv4 range", Args: cobra.NoArgs}
	setRange.Flags().StringVar(&rangeID, "id", "", "VPN ID")
	setRange.Flags().StringVar(&rangeCIDR, "cidr", "", "private IPv4 range, such as 10.203.0.0/24")
	setRange.Flags().IntVar(&rangeVersion, "version", 0, "current VPN version")
	for _, flag := range []string{"id", "cidr", "version"} {
		required(setRange, flag)
	}
	setRange.RunE = func(*cobra.Command, []string) error {
		if _, err := uuid.Parse(rangeID); err != nil {
			return err
		}
		client, _, err := o.account(false)
		if err != nil {
			return err
		}
		var result any
		if err = client.Do(o.ctx, "PATCH", "/api/vpns/"+rangeID, map[string]any{"ipv4_cidr": rangeCIDR, "version": rangeVersion}, &result, ""); err != nil {
			return err
		}
		return o.print(result)
	}
	group.AddCommand(setRange)
	approval := &cobra.Command{Use: "device", Short: "Inspect and approve device requests as the account owner"}
	root.AddCommand(approval)
	for _, operation := range []string{"inspect", "approve", "deny"} {
		var code, recipientFingerprint string
		command := &cobra.Command{Use: operation, Args: cobra.NoArgs}
		command.Flags().StringVar(&code, "code", "", "device user code")
		if operation == "approve" {
			command.Flags().StringVar(&recipientFingerprint, "recipient-fingerprint", "", "fingerprint printed by agenttail vpn join on the requesting CLI; prompted if omitted")
		}
		required(command, "code")
		command.RunE = func(*cobra.Command, []string) error { return o.approveDevice(code, operation, recipientFingerprint) }
		approval.AddCommand(command)
	}
}
func (o *options) approveDevice(code, operation, expectedRecipient string) error {
	client, s, err := o.account(false)
	if err != nil {
		return err
	}
	password, err := prompt("Account password", true)
	if err != nil {
		return err
	}
	derived, err := o.derive(client, s.Email, password)
	password = ""
	if err != nil {
		return err
	}
	defer clear(derived.E)
	confirm := map[string]any{"code": code, "password": derived.Auth}
	if operation == "deny" {
		var result any
		if err = client.Do(o.ctx, "POST", "/api/device/deny", confirm, &result, ""); err != nil {
			return err
		}
		return o.print(result)
	}
	if operation == "approve" && expectedRecipient == "" {
		expectedRecipient, err = prompt("Recipient fingerprint from the requesting CLI", false)
		if err != nil {
			return err
		}
	}
	expectedRecipient = strings.TrimSpace(expectedRecipient)
	var inspected struct {
		ID        string `json:"request_id"`
		CLI       string `json:"cli_label"`
		Recipient string `json:"ephemeral_public_key"`
		Expires   int64  `json:"expires_at"`
		Name      string `json:"name"`
		VPN       struct {
			ID      string `json:"vpn_id"`
			Name    string `json:"name"`
			Version int    `json:"version"`
		} `json:"vpn"`
	}
	if err = client.Do(o.ctx, "POST", "/api/device/inspect", confirm, &inspected, ""); err != nil {
		return err
	}
	if operation == "approve" {
		if err := cryptobox.VerifyRecipientFingerprint(inspected.Recipient, inspected.ID, expectedRecipient); err != nil {
			return &api.Error{Code: "FORBIDDEN", Message: "recipient fingerprint mismatch; copy it from agenttail vpn join on the requesting CLI"}
		}
	}
	recipientFingerprint, err := cryptobox.RecipientFingerprint(inspected.Recipient, inspected.ID)
	if err != nil {
		return err
	}
	if err = o.print(map[string]any{"code": code, "vpn": inspected.VPN.Name, "device": inspected.Name, "recipient_fingerprint": recipientFingerprint, "recipient_verified": operation == "approve", "cli": inspected.CLI, "expires_at": inspected.Expires}); err != nil {
		return err
	}
	if operation == "inspect" {
		return nil
	}
	yes, err := prompt("Add this device to this VPN? Type yes", false)
	if err != nil {
		return err
	}
	if yes != "yes" {
		return &api.Error{Code: "ACCESS_DENIED", Message: "approval cancelled"}
	}
	v, _, err := o.unlock(client, s.OwnerID, derived.E)
	if err != nil {
		return err
	}
	defer clear(v)
	pair, err := cryptobox.GenerateWireGuard()
	if err != nil {
		return err
	}
	defer clear(pair.Private)
	id := uuid.NewString()
	box, err := cryptobox.Seal(v, pair.Private, cryptobox.KeyAAD(s.OwnerID, id, pair.Public))
	if err != nil {
		return err
	}
	transfer, err := cryptobox.SealTransfer(inspected.Recipient, inspected.ID, id, pair.Private, expectedRecipient)
	if err != nil {
		return err
	}
	confirm["request_id"] = inspected.ID
	confirm["vpn_id"] = inspected.VPN.ID
	confirm["key_id"] = id
	confirm["public_key"] = pair.Public
	confirm["encrypted_private_key"] = box
	confirm["version"] = inspected.VPN.Version
	confirm["encrypted_transfer"] = transfer
	var result any
	if err = client.Do(o.ctx, "POST", "/api/device/approve", confirm, &result, ""); err != nil {
		return err
	}
	return o.print(result)
}
