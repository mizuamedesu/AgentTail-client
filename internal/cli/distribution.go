// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/agent"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/distribution"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/service"
	"github.com/spf13/cobra"
)

func (o *options) addDistribution(root *cobra.Command) {
	var bundle, source string
	var noService bool
	install := &cobra.Command{Use: "install", Short: "Install a verified native release and boot service", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		planned := o.config
		if err := o.saveOrigin(&planned); err != nil {
			return err
		}
		m, err := distribution.New(o.state)
		if err != nil {
			return err
		}
		existing, err := m.Record()
		if err != nil {
			return err
		}
		r, err := m.Apply(o.ctx, bundle, source, noService, existing != nil)
		if err != nil {
			return err
		}
		if err = o.state.Update(func(c *localstate.Config) error {
			if err := o.saveOrigin(c); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
		return o.print(r)
	}}
	install.Flags().StringVar(&bundle, "bundle", "", "directory containing manifest.txt, manifest.sig and native artifacts")
	install.Flags().StringVar(&source, "source", distribution.DefaultSource, "HTTPS update source")
	install.Flags().BoolVar(&noService, "no-service", false, "install files only; run the agent in the foreground")
	required(install, "bundle")
	root.AddCommand(install)
	var updateBundle, updateSource string
	update := &cobra.Command{Use: "update", Short: "Verify and activate a newer signed release; preserve native credentials", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		m, err := distribution.New(o.state)
		if err != nil {
			return err
		}
		r, err := m.Record()
		if err != nil {
			return err
		}
		if r == nil {
			return errors.New("run the installer before updating")
		}
		s := updateSource
		if s == "" {
			s = r.Source
		}
		dir := updateBundle
		if dir == "" {
			var clean func()
			dir, clean, err = distribution.Download(o.ctx, s)
			if err != nil {
				return err
			}
			defer clean()
		}
		r, err = m.Apply(o.ctx, dir, s, false, true)
		if err != nil {
			return err
		}
		return o.print(r)
	}}
	update.Flags().StringVar(&updateBundle, "bundle", "", "use an offline signed bundle")
	update.Flags().StringVar(&updateSource, "source", "", "HTTPS source; release trust key remains pinned")
	root.AddCommand(update)
	var yes, offline, purge bool
	uninstall := &cobra.Command{Use: "uninstall", Short: "Revoke local authorizations, remove native secrets, service and executable", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if !yes {
			return errors.New("uninstall requires --yes; local authorizations will be revoked and removed")
		}
		return o.uninstall(offline, purge)
	}}
	uninstall.Flags().BoolVar(&yes, "yes", false, "confirm uninstalling this machine's AgentTail client")
	uninstall.Flags().BoolVar(&offline, "offline", false, "remove locally without remote revocation; revoke these devices in Web UI later")
	uninstall.Flags().BoolVar(&purge, "purge", false, "also remove known local configuration and agent log files")
	root.AddCommand(uninstall)
	root.AddCommand(&cobra.Command{Use: "_check-secrets", Hidden: true, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		for _, k := range o.config.Keys {
			credential, err := o.state.LoadKey(k)
			clear(credential.Private)
			if err != nil {
				return err
			}
		}
		for _, admin := range []bool{false, true} {
			_, err := o.state.LoadSession(admin)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return o.print(map[string]any{"native_credentials_readable": true, "version": o.version})
	}})
}

func (o *options) uninstall(offline, purge bool) error {
	m, err := distribution.New(o.state)
	if err != nil {
		return err
	}
	pending := []string{}
	deferred, err := m.Remove(o.ctx, func(r *distribution.Record) error {
		if o.server != o.config.Server && len(o.config.Keys) > 0 {
			return errors.New("configured server does not match local credentials")
		}
		if err = o.state.Update(func(c *localstate.Config) error {
			for i := range c.Keys {
				c.Keys[i].AutoUp = false
			}
			return nil
		}); err != nil {
			return err
		}
		// Stop the foreground agent's tunnels too; service uninstall alone only
		// stops a service-managed daemon. Do not delete credentials while in use.
		for _, k := range o.config.Keys {
			e := agent.LocalRequest(o.ctx, o.state.Store.Dir, k.ID, "down", nil)
			var p *api.Error
			if e != nil && !(errors.As(e, &p) && p.Code == "AGENT_OFFLINE") {
				return e
			}
		}
		if r.Service {
			if err = service.Uninstall(); err != nil {
				return err
			}
		}
		var unlock func()
		if r.Service {
			wait, cancel := context.WithTimeout(o.ctx, 30*time.Second)
			defer cancel()
			unlock, err = o.state.WaitAgentLock(wait)
		} else {
			unlock, err = o.state.AgentLock()
		}
		if errors.Is(err, localstate.ErrAgentRunning) || errors.Is(err, context.DeadlineExceeded) {
			return errors.New("agent is still running; stop any foreground agenttail agent before uninstalling")
		}
		if err != nil {
			return err
		}
		defer unlock()
		for _, k := range o.config.Keys {
			if !offline {
				credential, e := o.state.LoadKey(k)
				if e != nil {
					return e
				}
				clear(credential.Private)
				client, e := o.client(credential.Token)
				if e != nil {
					return e
				}
				e = client.Do(o.ctx, "POST", "/api/agent/logout", map[string]any{}, nil, "")
				var p *api.Error
				if e != nil && !(errors.As(e, &p) && p.Code == "UNAUTHENTICATED") {
					return e
				}
			} else {
				pending = append(pending, k.GrantID)
			}
			if err = o.state.Store.Delete("key/" + k.ID); err != nil {
				return err
			}
			if err = o.state.Update(func(c *localstate.Config) error {
				var keep []localstate.Key
				for _, key := range c.Keys {
					if key.ID != k.ID {
						keep = append(keep, key)
					}
				}
				c.Keys = keep
				return nil
			}); err != nil {
				return err
			}
		}
		for _, admin := range []bool{false, true} {
			scope := "account"
			if admin {
				scope = "admin"
			}
			s, e := o.state.LoadSession(admin)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return e
			}
			if !offline {
				client, e := api.New(s.Server, s.Token, o.config.AllowLocalHTTP)
				if e != nil {
					return e
				}
				e = client.Do(o.ctx, "POST", "/api/auth/sign-out", map[string]any{}, nil, "")
				var p *api.Error
				if e != nil && !(errors.As(e, &p) && p.Code == "UNAUTHENTICATED") {
					return e
				}
			}
			if err = o.state.Store.Delete("session/" + scope); err != nil {
				return err
			}
		}
		if purge {
			if err = o.state.Store.Purge(); err != nil {
				return err
			}
			for _, name := range []string{"config.json", "agent.log"} {
				if err = os.Remove(filepath.Join(o.state.Store.Dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return o.print(map[string]any{"uninstalled": true, "file_removal_requires_reboot": deferred, "remote_revocation_pending": pending, "sessions_need_web_revocation": offline, "config_removed": purge})
}
