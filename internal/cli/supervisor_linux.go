// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"github.com/mizuamedesu/AgentTail-client/internal/service"
	"github.com/spf13/cobra"
)

func (o *options) addSupervisor(group *cobra.Command) {
	group.AddCommand(&cobra.Command{Use: "supervise", Hidden: true, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return service.Supervise(o.ctx)
	}})
}
