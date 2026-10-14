// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"errors"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func (o *options) addResourceEdits(group *cobra.Command, path, remove string) {
	for _, action := range []string{"show", "rename", remove} {
		var id, name string
		var version int
		cmd := &cobra.Command{Use: action, Args: cobra.NoArgs}
		cmd.Flags().StringVar(&id, "id", "", "resource ID")
		required(cmd, "id")
		if action != "show" {
			cmd.Flags().IntVar(&version, "version", 0, "current version")
			required(cmd, "version")
		}
		if action == "rename" {
			cmd.Flags().StringVar(&name, "name", "", "new name")
			required(cmd, "name")
		}
		cmd.RunE = func(*cobra.Command, []string) error {
			if _, err := uuid.Parse(id); err != nil {
				return errors.New("invalid resource ID")
			}
			client, _, err := o.account(false)
			if err != nil {
				return err
			}
			method, url := "GET", path+"/"+id
			var body any
			if action == "rename" {
				method = "PATCH"
				body = map[string]any{"name": name, "version": version}
			}
			if action == remove {
				method = "POST"
				url += "/" + remove
				body = map[string]any{"version": version}
			}
			var result any
			if err = client.Do(o.ctx, method, url, body, &result, ""); err != nil {
				return err
			}
			return o.print(result)
		}
		group.AddCommand(cmd)
	}
}
