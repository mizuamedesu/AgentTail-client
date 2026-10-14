// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux && !riscv64

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const Name = "agenttail.service"
const unitPath = "/etc/systemd/system/agenttail.service"

func unitQuote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`).Replace(value) + `"`
}
func unit(executable, directory string) string {
	return fmt.Sprintf(`[Unit]
Description=AgentTail encrypted virtual-IP network
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=%s --state-dir %s agent run
Restart=on-failure
RestartSec=10
TimeoutStopSec=20
User=root
UMask=0077
LimitCORE=0
NoNewPrivileges=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
`, unitQuote(executable), unitQuote(directory))
}
func Install(executable, directory string) error {
	if useSupervisor() {
		return applianceService.install(executable, directory)
	}
	if err := Validate(executable, directory); err != nil {
		return err
	}
	if err := write(unitPath, []byte(unit(executable, directory))); err != nil {
		return err
	}
	if err := run("/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	return run("/usr/bin/systemctl", "enable", "--now", Name)
}
func useSupervisor() bool {
	if _, err := os.Stat(filepath.Join(applianceService.configDir, "config.json")); err == nil {
		return true
	}
	if _, err := os.Stat(unitPath); err == nil {
		return false
	}
	return !systemdRunning()
}

func systemdRunning() bool {
	info, err := os.Stat("/run/systemd/system")
	if err != nil || !info.IsDir() {
		return false
	}
	info, err = os.Stat("/usr/bin/systemctl")
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

func Start() error {
	if useSupervisor() {
		return applianceService.start()
	}
	return run("/usr/bin/systemctl", "start", Name)
}
func Stop() error {
	if useSupervisor() {
		return applianceService.stop()
	}
	return run("/usr/bin/systemctl", "stop", Name)
}
func Restart() error {
	if useSupervisor() {
		if err := Stop(); err != nil {
			return err
		}
		return Start()
	}
	return run("/usr/bin/systemctl", "restart", Name)
}
func Inspect() (Status, error) {
	if useSupervisor() {
		return applianceService.inspect()
	}
	result := Status{Name: Name}
	_, err := os.Stat(unitPath)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Installed = true
	result.Running = run("/usr/bin/systemctl", "is-active", "--quiet", Name) == nil
	return result, nil
}
func Uninstall() error {
	if useSupervisor() {
		return applianceService.uninstall()
	}
	status, err := Inspect()
	if err != nil || !status.Installed {
		return err
	}
	if err = run("/usr/bin/systemctl", "disable", "--now", Name); err != nil {
		return err
	}
	if err = os.Remove(unitPath); err != nil {
		return err
	}
	return run("/usr/bin/systemctl", "daemon-reload")
}
func Run(ctx context.Context, agent func(context.Context) error) error { return agent(ctx) }
