// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"errors"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/agent"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/netdev"
	"github.com/mizuamedesu/AgentTail-client/internal/service"
	"github.com/spf13/cobra"
)

func (o *options) addNetwork(root *cobra.Command) {
	for _, action := range []string{"up", "down", "status", "sync"} {
		action := action
		var name string
		command := &cobra.Command{Use: action, Short: action + " a joined VPN", Args: cobra.NoArgs}
		command.Flags().StringVar(&name, "name", "", "VPN name or ID")
		readNetwork := o.networkFlags(command, action == "up")
		if action != "status" {
			required(command, "name")
		}
		command.RunE = func(*cobra.Command, []string) error {
			if err := readNetwork(); err != nil {
				return err
			}
			if len(o.config.Keys) > 0 && o.config.Server != o.server {
				return &api.Error{Code: "FORBIDDEN", Message: "local keys belong to a different server"}
			}
			id := ""
			if name != "" {
				key, err := o.config.Find(name)
				if err != nil {
					return err
				}
				id = key.ID
			}
			return o.requestNetwork(action, id, name)
		}
		for _, group := range root.Commands() {
			if group.Name() == "vpn" {
				group.AddCommand(command)
			}
		}
	}
	group := &cobra.Command{Use: "agent", Short: "Run the privileged machine agent"}
	group.AddCommand(&cobra.Command{Use: "run", Short: "Run in the foreground (service managers use this command)", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return service.Run(o.ctx, func(ctx context.Context) error { return agent.Serve(ctx, o.state) })
	}})
	o.addSupervisor(group)
	root.AddCommand(group)
}

func (o *options) requestNetwork(action, id, name string) error {
	if action == "up" {
		if err := o.saveNetwork(id); err != nil {
			return err
		}
	}
	var result any
	err := agent.LocalRequest(o.ctx, o.state.Store.Dir, id, action, &result)
	if err != nil {
		var p *api.Error
		if action == "status" && errors.As(err, &p) && p.Code == "AGENT_OFFLINE" {
			return o.print(map[string]any{"agent": "stopped", "keys": o.config.Keys})
		}
		return err
	}
	if action == "up" {
		// Allow the background agent to recover from an initial failed sync. Its
		// status can also still contain a problem from before this up request.
		ctx, cancel := context.WithTimeout(o.ctx, 2*agent.SyncInterval+agent.RequestTimeout)
		defer cancel()
		status, err := waitForActivation(ctx, 250*time.Millisecond, func(ctx context.Context) (agent.Status, error) {
			var state struct {
				Keys []agent.Status `json:"keys"`
			}
			if err := agent.LocalRequest(ctx, o.state.Store.Dir, id, "status", &state); err != nil {
				return agent.Status{}, err
			}
			if len(state.Keys) != 1 || state.Keys[0].ID != id {
				return agent.Status{}, &api.Error{Code: "INTERNAL", Message: "local agent returned an unexpected VPN status"}
			}
			return state.Keys[0], nil
		})
		if errors.Is(err, context.DeadlineExceeded) && o.ctx.Err() == nil {
			code := status.Problem
			if code == "" {
				code = "NETWORK"
			}
			if code == "CONFIGURATION" && status.NetworkMode != "userspace" {
				return &api.Error{Code: code, Message: "native VPN interface could not be configured; a restricted container can use agenttail vpn up --name " + name + " --userspace (loopback SOCKS5 TCP proxy)"}
			}
			return &api.Error{Code: code, Message: "VPN activation is still pending; the agent will retry automatically; see agenttail vpn status --name " + name}
		}
		if err != nil {
			return err
		}
		if status.NetworkMode == "userspace" && !o.json {
			o.notice("Userspace VPN ready. TCP connections use SOCKS5 at %s (VPN peer IPv4 addresses only).", status.SOCKS5)
		}
		return o.print(status)
	}
	return o.print(result)
}

func (o *options) networkFlags(command *cobra.Command, enabled bool) func() error {
	if !enabled {
		return func() error { return nil }
	}
	var userspace bool
	var socks string
	command.Flags().BoolVar(&userspace, "userspace", false, "use a TUN-free userspace VPN with a loopback SOCKS5 TCP proxy; --userspace=false restores native TUN")
	command.Flags().StringVar(&socks, "socks5", netdev.DefaultSOCKS5, "userspace SOCKS5 loopback IP:port (implies --userspace)")
	return func() error {
		if !command.Flags().Changed("userspace") && !command.Flags().Changed("socks5") {
			return nil
		}
		if command.Flags().Changed("socks5") {
			if command.Flags().Changed("userspace") && !userspace {
				return errors.New("--socks5 cannot be combined with --userspace=false")
			}
			userspace = true
		}
		settings := netdev.Settings{Mode: "native"}
		if userspace {
			settings = netdev.Settings{Mode: "userspace", SOCKS5: socks}
		}
		settings, err := settings.Normalized()
		if err == nil {
			o.network = &settings
		}
		return err
	}
}

func (o *options) saveNetwork(id string) error {
	if o.network == nil {
		return nil
	}
	return o.state.Update(func(c *localstate.Config) error {
		for i := range c.Keys {
			if c.Keys[i].ID == id {
				if c.Server != o.server {
					return errors.New("local keys belong to a different server")
				}
				c.Keys[i].Network = *o.network
				return nil
			}
		}
		return errors.New("key is no longer authorized locally")
	})
}

func waitForActivation(ctx context.Context, interval time.Duration, poll func(context.Context) (agent.Status, error)) (agent.Status, error) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var last agent.Status
	for {
		if err := ctx.Err(); err != nil {
			return last, err
		}
		status, err := poll(ctx)
		// A local IPC timeout must not hide cancellation or the activation deadline.
		if ctx.Err() != nil {
			return last, ctx.Err()
		}
		if err != nil {
			return last, err
		}
		last = status
		if status.State == "unauthorized" {
			return last, &api.Error{Code: "UNAUTHENTICATED", Message: "VPN authorization is no longer valid; log in again"}
		}
		if status.Desired == "down" {
			code := status.Problem
			if code == "" {
				code = "CONFLICT"
			}
			return last, &api.Error{Code: code, Message: "VPN activation was stopped; inspect agenttail vpn status"}
		}
		if status.State == "up" && status.Authorized && status.Desired == "up" {
			return last, nil
		}
		// Nonterminal problems remain retryable while desired_state is up. Do
		// not turn the first failed control request into a failed join.
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-tick.C:
		}
	}
}
