// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"github.com/mizuamedesu/AgentTail-client/internal/cli"
	"github.com/mizuamedesu/AgentTail-client/internal/platform"
	"os"
	"os/signal"
)

var version = "0.1.0-dev"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), platform.Signals()...)
	defer cancel()
	os.Exit(cli.Run(ctx, os.Args[1:], version))
}
