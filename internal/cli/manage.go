package cli

import (
	"errors"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func (o *options) read(command *cobra.Command, path string, administrator, pages bool) {
	command.RunE = func(*cobra.Command, []string) error {
		client, _, err := o.account(administrator)
		if err != nil {
			return err
		}
		var result any
		if pages {
			err = client.Pages(o.ctx, path, &result)
		} else {
			err = client.Do(o.ctx, "GET", path, nil, &result, "")
		}
		if err != nil {
			return err
		}
		return o.print(result)
	}
}
func (o *options) mutate(path, method string, input any, admin bool) error {
	client, _, err := o.account(admin)
	if err != nil {
		return err
	}
	var result any
	if err = client.Do(o.ctx, method, path, input, &result, ""); err != nil {
		return err
	}
	return o.print(result)
}
func (o *options) addManagement(root *cobra.Command) {
	devices := &cobra.Command{Use: "devices", Short: "Account-level management of enrolled devices"}
	root.AddCommand(devices)
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs}
	o.read(list, "/api/manage/devices", false, true)
	devices.AddCommand(list)
	var grant string
	revoke := &cobra.Command{Use: "revoke", Args: cobra.NoArgs}
	revoke.Flags().StringVar(&grant, "grant-id", "", "grant ID")
	required(revoke, "grant-id")
	revoke.RunE = func(*cobra.Command, []string) error {
		if _, err := uuid.Parse(grant); err != nil {
			return err
		}
		return o.mutate("/api/manage/devices/"+grant+"/revoke", "POST", map[string]any{}, false)
	}
	devices.AddCommand(revoke)
	var keyID, action string
	command := &cobra.Command{Use: "command", Short: "Send up/down/sync to an online agent", Args: cobra.NoArgs}
	command.Flags().StringVar(&keyID, "key-id", "", "owned key ID")
	command.Flags().StringVar(&action, "action", "", "up, down or sync")
	required(command, "key-id", "action")
	command.RunE = func(*cobra.Command, []string) error {
		if _, err := uuid.Parse(keyID); err != nil {
			return err
		}
		return o.mutate("/api/manage/keys/"+keyID+"/commands", "POST", map[string]any{"action": action}, false)
	}
	devices.AddCommand(command)
	var commandID string
	result := &cobra.Command{Use: "result", Args: cobra.NoArgs}
	result.Flags().StringVar(&commandID, "command-id", "", "command ID")
	required(result, "command-id")
	result.RunE = func(*cobra.Command, []string) error {
		if _, err := uuid.Parse(commandID); err != nil {
			return err
		}
		c, _, err := o.account(false)
		if err != nil {
			return err
		}
		var data any
		if err = c.Do(o.ctx, "GET", "/api/manage/commands/"+commandID, nil, &data, ""); err != nil {
			return err
		}
		return o.print(data)
	}
	devices.AddCommand(result)
	acl := &cobra.Command{Use: "acl", Short: "Owner mesh ACL rules"}
	root.AddCommand(acl)
	aclList := &cobra.Command{Use: "list", Args: cobra.NoArgs}
	o.read(aclList, "/api/manage/acl", false, false)
	acl.AddCommand(aclList)
	var source, target string
	var allow bool
	var aclVersion int
	set := &cobra.Command{Use: "set", Args: cobra.NoArgs}
	set.Flags().StringVar(&source, "source", "", "source key ID")
	set.Flags().StringVar(&target, "target", "", "target key ID")
	set.Flags().BoolVar(&allow, "allow", false, "allow both peers (otherwise deny)")
	set.Flags().IntVar(&aclVersion, "version", 0, "current rule version; zero creates a rule")
	required(set, "source", "target")
	set.RunE = func(*cobra.Command, []string) error {
		return o.mutate("/api/manage/acl", "PUT", map[string]any{"source_key_id": source, "target_key_id": target, "allow": allow, "version": aclVersion}, false)
	}
	acl.AddCommand(set)
	billing := &cobra.Command{Use: "billing", Short: "Free allowance, persistent packs and purchase ledger"}
	root.AddCommand(billing)
	for name, path := range map[string]string{"status": "/api/billing", "purchases": "/api/billing/purchases", "ledger": "/api/billing/ledger"} {
		c := &cobra.Command{Use: name, Args: cobra.NoArgs}
		o.read(c, path, false, name != "status")
		billing.AddCommand(c)
	}
	var kind, purchase string
	var quantity int
	buy := &cobra.Command{Use: "buy", Short: "Create a Stripe Checkout link; payment still requires user completion", Args: cobra.NoArgs}
	buy.Flags().StringVar(&kind, "kind", "", "transfer or keys")
	buy.Flags().IntVar(&quantity, "quantity", 1, "number of $1 packs")
	buy.Flags().StringVar(&purchase, "purchase-id", "", "reuse this ID when retrying an uncertain Checkout request")
	required(buy, "kind")
	buy.RunE = func(*cobra.Command, []string) error {
		if purchase == "" {
			purchase = uuid.NewString()
		}
		if _, err := uuid.Parse(purchase); err != nil {
			return err
		}
		o.notice("Purchase ID: %s (reuse it to retry safely)", purchase)
		return o.mutate("/api/billing/checkout", "POST", map[string]any{"purchase_id": purchase, "kind": kind, "quantity": quantity}, false)
	}
	billing.AddCommand(buy)
	admin, _, _ := root.Find([]string{"admin"})
	for name, path := range map[string]string{"users": "/api/admin/users", "metrics": "/api/admin/metrics", "audit": "/api/admin/audit"} {
		c := &cobra.Command{Use: name, Args: cobra.NoArgs}
		o.read(c, path, true, name == "users")
		admin.AddCommand(c)
	}
	settings := &cobra.Command{Use: "settings", Short: "Read or replace versioned global limits"}
	admin.AddCommand(settings)
	get := &cobra.Command{Use: "get", Args: cobra.NoArgs}
	o.read(get, "/api/admin/settings", true, false)
	settings.AddCommand(get)
	var kill, registration bool
	var version, connections, turn int
	update := &cobra.Command{Use: "set", Args: cobra.NoArgs}
	update.Flags().BoolVar(&kill, "kill-switch", false, "stop all VPN traffic")
	update.Flags().BoolVar(&registration, "registration", true, "allow registration")
	update.Flags().IntVar(&version, "version", 0, "current settings version")
	update.Flags().IntVar(&connections, "max-connections", 100, "global live agent limit")
	update.Flags().IntVar(&turn, "max-turn-credentials", 100, "global TURN credential limit")
	required(update, "version", "kill-switch", "registration", "max-connections", "max-turn-credentials")
	update.RunE = func(*cobra.Command, []string) error {
		return o.mutate("/api/admin/settings", "PUT", map[string]any{"version": version, "kill_switch": kill, "registration_enabled": registration, "max_total_connections": connections, "max_turn_credentials": turn}, true)
	}
	settings.AddCommand(update)
	var user string
	var disabled, relay bool
	var userVersion, maxConnections, rate int
	limits := &cobra.Command{Use: "limits", Short: "Update an account's versioned limits", Args: cobra.NoArgs}
	limits.Flags().StringVar(&user, "user-id", "", "account ID")
	limits.Flags().IntVar(&userVersion, "version", 0, "billing-account version")
	limits.Flags().BoolVar(&disabled, "disabled", false, "disable the account and revoke sessions/grants")
	limits.Flags().BoolVar(&relay, "relay-disabled", false, "stop relay only")
	limits.Flags().IntVar(&maxConnections, "max-connections", 10, "live agent limit")
	limits.Flags().IntVar(&rate, "bytes-per-second", 1250000, "managed network rate limit across this account (direct and relay)")
	required(limits, "user-id", "version", "disabled", "relay-disabled", "max-connections", "bytes-per-second")
	limits.RunE = func(*cobra.Command, []string) error {
		if _, err := uuid.Parse(user); err != nil {
			return errors.New("invalid user ID")
		}
		return o.mutate("/api/admin/users/"+user, "PATCH", map[string]any{"version": userVersion, "disabled": disabled, "relay_disabled": relay, "max_connections": maxConnections, "bytes_per_second": rate}, true)
	}
	admin.AddCommand(limits)
}
