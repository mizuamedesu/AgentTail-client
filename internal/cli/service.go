package cli

import (
	"github.com/mizuamedesu/AgentTail/internal/service"
	"github.com/spf13/cobra"
	"os"
)

func (o *options) addService(root *cobra.Command) {
	group := &cobra.Command{Use: "service", Short: "Manage the native boot service"}
	for _, action := range []string{"install", "start", "stop", "restart", "status", "uninstall"} {
		action := action
		group.AddCommand(&cobra.Command{Use: action, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
			var err error
			switch action {
			case "install":
				executable, e := os.Executable()
				if e != nil {
					return e
				}
				err = service.Install(executable, o.state.Store.Dir)
			case "start":
				err = service.Start()
			case "stop":
				err = service.Stop()
			case "restart":
				err = service.Restart()
			case "uninstall":
				err = service.Uninstall()
			}
			if err != nil {
				return err
			}
			status, err := service.Inspect()
			if err != nil {
				return err
			}
			return o.print(status)
		}})
	}
	root.AddCommand(group)
}
