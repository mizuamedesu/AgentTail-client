// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"github.com/mizuamedesu/AgentTail-client/internal/skills"
	"github.com/spf13/cobra"
)

func (o *options) addSkills(root *cobra.Command) {
	group := &cobra.Command{Use: "skills", Short: "Install public CLI guidance for detected Codex and Claude Code"}
	group.AddCommand(&cobra.Command{Use: "install", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		result, err := skills.Install()
		if err != nil {
			return err
		}
		return o.print(result)
	}})
	root.AddCommand(group)
}
