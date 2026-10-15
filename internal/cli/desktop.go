// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"errors"
	"sort"

	"github.com/mizuamedesu/AgentTail-client/internal/agent"
	"github.com/mizuamedesu/AgentTail-client/internal/api"
	"github.com/mizuamedesu/AgentTail-client/internal/desktop"
	"github.com/mizuamedesu/AgentTail-client/internal/desktop/bridge"
	"github.com/mizuamedesu/AgentTail-client/internal/distribution"
	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/service"
	"github.com/spf13/cobra"
)

func (o *options) addDesktop(root *cobra.Command) {
	gui := &cobra.Command{Use: "gui", Short: "Open the desktop VPN manager", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return desktop.OpenWindow() }}
	gui.AddCommand(&cobra.Command{Use: "install", Short: "Install the desktop manager matching the installed CLI", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		m, err := distribution.New(o.state)
		if err != nil {
			return err
		}
		record, err := m.InstallDesktop(o.ctx, "")
		if err != nil {
			return err
		}
		return o.print(record)
	}})
	gui.AddCommand(&cobra.Command{Use: "uninstall", Short: "Remove the desktop manager and keep the VPN service", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		m, err := distribution.New(o.state)
		if err != nil {
			return err
		}
		if err = m.RemoveDesktop(); err != nil {
			return err
		}
		return o.print(map[string]bool{"gui_removed": true})
	}})
	root.AddCommand(gui)
	var sessionFile string
	command := &cobra.Command{Use: "desktop-helper", Hidden: true, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		session, err := desktop.ReadSession(sessionFile, o.version)
		if err != nil {
			return err
		}
		server := bridge.Server{Session: session, Backend: &desktopBackend{state: o.state, version: o.version, local: o.local}}
		return server.Serve(o.ctx)
	}}
	command.Flags().StringVar(&sessionFile, "session-file", "", "private desktop session file")
	required(command, "session-file")
	root.AddCommand(command)
}

type desktopBackend struct {
	state   *localstate.State
	version string
	local   bool
}

func (b *desktopBackend) Status(ctx context.Context) (desktop.Snapshot, error) {
	s := desktop.Snapshot{Version: b.version, VPNs: []desktop.VPN{}}
	unlock, err := localstate.CLILock(b.state.Store.Dir+"/cli.lock", false)
	if err != nil {
		return s, err
	}
	defer unlock()
	config, err := b.state.Read()
	if err != nil {
		return s, err
	}
	var live struct {
		Keys []agent.Status `json:"keys"`
	}
	err = agent.LocalRequest(ctx, b.state.Store.Dir, "", "status", &live)
	var problem *api.Error
	if err != nil && (!errors.As(err, &problem) || problem.Code != "AGENT_OFFLINE") {
		return s, err
	}
	s.Running = err == nil
	byID := map[string]agent.Status{}
	for _, item := range live.Keys {
		byID[item.ID] = item
	}
	for _, key := range config.Keys {
		mode := key.Network.Mode
		if mode == "" {
			mode = "native"
		}
		row := desktop.VPN{ID: key.ID, Name: key.Name, VPNID: key.VPNID, State: "stopped", Desired: "down", Mode: mode, SOCKS5: key.Network.SOCKS5}
		if key.AutoUp {
			row.Desired = "up"
		}
		if current, ok := byID[key.ID]; ok {
			row.State, row.Desired, row.Address = current.State, current.Desired, current.Address
			row.Mode, row.SOCKS5, row.Problem = current.NetworkMode, current.SOCKS5, current.Problem
			row.BytesSent, row.BytesRead = current.Sent, current.Received
			for _, peer := range current.Peers {
				if peer.State == "connected" {
					row.Peers++
				}
			}
		}
		s.VPNs = append(s.VPNs, row)
	}
	sort.Slice(s.VPNs, func(i, j int) bool {
		if s.VPNs[i].Name == s.VPNs[j].Name {
			return s.VPNs[i].ID < s.VPNs[j].ID
		}
		return s.VPNs[i].Name < s.VPNs[j].Name
	})
	return s, nil
}

func (b *desktopBackend) Toggle(ctx context.Context, action desktop.Action) error {
	unlock, err := localstate.CLILock(b.state.Store.Dir+"/cli.lock", false)
	if err != nil {
		return err
	}
	defer unlock()
	config, err := b.state.Read()
	if err != nil {
		return err
	}
	var selected *localstate.Key
	for _, key := range config.Keys {
		if key.ID == action.ID {
			selected = &key
			break
		}
	}
	if selected == nil || action.Action != "up" && action.Action != "down" && action.Action != "leave" {
		return errors.New("this VPN is not installed on this machine")
	}
	if action.Action == "leave" {
		o := options{ctx: ctx, state: b.state, config: config, server: config.Server, local: b.local}
		return o.leaveDevice(*selected)
	}
	return agent.LocalRequest(ctx, b.state.Store.Dir, action.ID, action.Action, nil)
}

func (b *desktopBackend) StartService(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	unlock, err := localstate.CLILock(b.state.Store.Dir+"/cli.lock", false)
	if err != nil {
		return err
	}
	defer unlock()
	return service.Start()
}
