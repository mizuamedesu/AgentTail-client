// SPDX-License-Identifier: GPL-3.0-or-later

package service

import "context"

const Name = "agenttail"

func Install(executable, directory string) error {
	return applianceService.install(executable, directory)
}
func Start() error { return applianceService.start() }
func Stop() error  { return applianceService.stop() }
func Restart() error {
	if err := Stop(); err != nil {
		return err
	}
	return Start()
}
func Inspect() (Status, error)                                         { return applianceService.inspect() }
func Uninstall() error                                                 { return applianceService.uninstall() }
func Run(ctx context.Context, agent func(context.Context) error) error { return agent(ctx) }
