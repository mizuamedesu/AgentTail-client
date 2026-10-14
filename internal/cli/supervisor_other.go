// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux

package cli

import "github.com/spf13/cobra"

func (o *options) addSupervisor(group *cobra.Command) {}
