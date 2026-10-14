// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !acceptance

package cli

import "github.com/spf13/cobra"

func addAcceptance(*cobra.Command, *options) {}
