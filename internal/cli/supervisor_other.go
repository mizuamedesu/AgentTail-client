//go:build !linux || !riscv64

package cli

import "github.com/spf13/cobra"

func (o *options) addSupervisor(group *cobra.Command) {}
