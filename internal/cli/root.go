// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/netdev"
	"github.com/mizuamedesu/AgentTail-client/internal/notices"
	"github.com/mizuamedesu/AgentTail-client/internal/platform"
	"github.com/spf13/cobra"
)

const defaultServer = "https://agenttail-api.mizuame.app"

type options struct {
	version   string
	server    string
	webOrigin string
	directory string
	json      bool
	browser   bool
	local     bool
	state     *localstate.State
	config    localstate.Config
	ctx       context.Context
	network   *netdev.Settings
}
type forwardedExit struct{ code int }

func (e *forwardedExit) Error() string { return "elevated command completed" }

func Run(ctx context.Context, args []string, version string) int {
	o := &options{ctx: ctx, version: version}
	var releaseCLI func()
	defer func() {
		if releaseCLI != nil {
			releaseCLI()
		}
	}()
	root := &cobra.Command{Use: "agenttail", Short: "AgentTail encrypted virtual-IP network", SilenceErrors: true, SilenceUsage: true}
	root.PersistentFlags().StringVar(&o.server, "server", "", "control server HTTPS origin")
	root.PersistentFlags().StringVar(&o.webOrigin, "web-origin", "", "trusted Web UI HTTPS origin for approval and recovery")
	root.PersistentFlags().StringVar(&o.directory, "state-dir", "", "private machine state directory")
	root.PersistentFlags().BoolVar(&o.json, "json", false, "emit compact JSON")
	root.PersistentFlags().BoolVar(&o.browser, "browser", true, "offer to open device approval in a local browser; --browser=false prints the link")
	root.PersistentFlags().BoolVar(&o.local, "allow-local-http", false, "allow loopback HTTP for development only")
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if cmd.Name() == "version" || cmd.Name() == "licenses" || cmd.Name() == "help" || cmd.Name() == "gui" || cmd.Parent() != nil && (cmd.Parent().Name() == "completion" || cmd.Parent().Name() == "skills") {
			return nil
		}
		if cmd.Parent() != nil && cmd.Parent().Name() == "ssh" && (cmd.Name() == "install-public" || cmd.Name() == "install-private") {
			return o.resolveOrigins()
		}
		run, code, err := platform.Elevate()
		if err != nil {
			return &api.Error{Code: "FORBIDDEN", Message: err.Error()}
		}
		if run {
			return &forwardedExit{code}
		}
		o.state, err = localstate.New(o.directory)
		if err != nil {
			return err
		}
		isAgent := cmd.Name() == "desktop-helper" || (cmd.Name() == "run" || cmd.Name() == "supervise") && cmd.Parent() != nil && cmd.Parent().Name() == "agent"
		if !isAgent && cmd.Name() != "_check-secrets" {
			exclusive := cmd.Name() == "install" || cmd.Name() == "update" || cmd.Name() == "uninstall"
			releaseCLI, err = localstate.CLILock(filepath.Join(o.state.Store.Dir, "cli.lock"), exclusive)
			if err != nil {
				return err
			}
		}
		o.config, err = o.state.Read()
		if err != nil {
			return err
		}
		return o.resolveOrigins()
	}
	root.AddCommand(&cobra.Command{Use: "version", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return o.print(map[string]any{"version": version, "api_version": 1})
	}})
	root.AddCommand(&cobra.Command{Use: "licenses", Short: "Show bundled third-party license notices", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return o.print(map[string]string{"license": "GPL-3.0-or-later", "source": notices.SourceURL, "license_text": notices.GPL, "notices": notices.Text})
	}})
	configure := &cobra.Command{Use: "configure", Short: "Configure the API and Web origins", Args: cobra.NoArgs}
	configure.RunE = func(*cobra.Command, []string) error { return o.configure() }
	root.AddCommand(configure)
	o.addAccount(root, false)
	o.addAccount(root, true)
	o.addKeys(root)
	o.addDevice(root)
	o.addSSH(root)
	o.addManagement(root)
	o.addNetwork(root)
	o.addDesktop(root)
	o.addService(root)
	o.addDistribution(root)
	o.addSkills(root)
	addAcceptance(root, o)
	root.SetArgs(args)
	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		if releaseCLI != nil {
			releaseCLI()
			releaseCLI = nil
		}
		o.showUpdateNotice(cmd)
		return 0
	}
	var forwarded *forwardedExit
	if errors.As(err, &forwarded) {
		return forwarded.code
	}
	var problem *api.Error
	if !errors.As(err, &problem) {
		problem = &api.Error{Code: "INVALID_REQUEST", Message: err.Error()}
	}
	if ctx.Err() != nil {
		problem = &api.Error{Code: "NETWORK", Message: "operation interrupted"}
	}
	encoder := json.NewEncoder(os.Stderr)
	encoder.SetEscapeHTML(false)
	encoder.Encode(map[string]any{"ok": false, "error": problem})
	return problem.ExitCode()
}
func (o *options) print(data any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if !o.json {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(map[string]any{"ok": true, "data": data})
}
func (o *options) client(token string) (*api.Client, error) { return api.New(o.server, token, o.local) }
func (o *options) account(administrator bool) (*api.Client, localstate.Session, error) {
	session, err := o.state.LoadSession(administrator)
	if err != nil {
		return nil, session, &api.Error{Code: "UNAUTHENTICATED", Message: "run agenttail account login (or agenttail admin login for administrator operations)"}
	}
	if strings.TrimRight(session.Server, "/") != strings.TrimRight(o.server, "/") {
		return nil, session, &api.Error{Code: "FORBIDDEN", Message: "stored session belongs to a different server"}
	}
	client, err := o.client(session.Token)
	if err != nil {
		return nil, session, err
	}
	path := "/api/account/me"
	if administrator {
		path = "/api/admin/me"
	}
	var me struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	}
	if err = client.Do(o.ctx, "GET", path, nil, &me, ""); err != nil {
		return nil, session, err
	}
	if me.ID != session.OwnerID {
		return nil, session, &api.Error{Code: "FORBIDDEN", Message: "account identity changed"}
	}
	return client, session, nil
}
func (o *options) saveOrigin(c *localstate.Config) error {
	if c.Server != "" && c.Server != o.server && len(c.Keys) > 0 {
		return errors.New("log out existing keys before changing servers")
	}
	c.Server = o.server
	c.WebOrigin = o.webOrigin
	c.AllowLocalHTTP = o.local
	return nil
}
func (o *options) configure() error {
	err := o.state.Update(func(c *localstate.Config) error {
		if err := o.saveOrigin(c); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return o.print(map[string]any{"server": o.server, "web_origin": o.webOrigin})
}
func required(command *cobra.Command, names ...string) {
	for _, name := range names {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}
func (o *options) notice(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
