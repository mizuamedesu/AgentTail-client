//go:build linux && !riscv64

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
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
func Start() error   { return run("/usr/bin/systemctl", "start", Name) }
func Stop() error    { return run("/usr/bin/systemctl", "stop", Name) }
func Restart() error { return run("/usr/bin/systemctl", "restart", Name) }
func Inspect() (Status, error) {
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
