// SPDX-License-Identifier: GPL-3.0-or-later

package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const Name = "io.agenttail.vpn"
const plistPath = "/Library/LaunchDaemons/io.agenttail.vpn.plist"

func xmlValue(value string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(value))
	return b.String()
}
func plist(executable, directory string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.agenttail.vpn</string>
<key>ProgramArguments</key><array><string>%s</string><string>--state-dir</string><string>%s</string><string>agent</string><string>run</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>10</integer><key>ExitTimeOut</key><integer>20</integer>
<key>UserName</key><string>root</string><key>Umask</key><integer>63</integer>
<key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
<key>HardResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
<key>StandardOutPath</key><string>%s</string><key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, xmlValue(executable), xmlValue(directory), xmlValue(filepath.Join(directory, "agent.log")), xmlValue(filepath.Join(directory, "agent.log")))
}
func Install(executable, directory string) error {
	if err := Validate(executable, directory); err != nil {
		return err
	}
	if err := Stop(); err != nil {
		return err
	}
	if err := write(plistPath, []byte(plist(executable, directory))); err != nil {
		return err
	}
	if err := run("/bin/launchctl", "enable", "system/"+Name); err != nil {
		return err
	}
	return run("/bin/launchctl", "bootstrap", "system", plistPath)
}
func Start() error {
	if err := run("/bin/launchctl", "enable", "system/"+Name); err != nil {
		return err
	}
	loaded, err := launchdLoaded(context.Background(), launchctl)
	if err != nil {
		return err
	}
	if !loaded {
		return run("/bin/launchctl", "bootstrap", "system", plistPath)
	}
	return run("/bin/launchctl", "kickstart", "system/"+Name)
}
func Stop() error {
	// bootout removes the running job from launchd, so KeepAlive cannot restart
	// it behind an intentional CLI stop. Removal may finish asynchronously.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return stopLaunchd(ctx, launchctl)
}
func Restart() error {
	if err := Stop(); err != nil {
		return err
	}
	return Start()
}

type launchctlCommand func(context.Context, ...string) error

func launchctl(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/bin/launchctl", args...).Run(); err != nil {
		return fmt.Errorf("launchctl %s failed: %w", args[0], err)
	}
	return nil
}

func launchdExit(err error, codes ...int) bool {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		for _, code := range codes {
			if exit.ExitCode() == code {
				return true
			}
		}
	}
	return false
}

func launchdLoaded(ctx context.Context, command launchctlCommand) (bool, error) {
	err := command(ctx, "print", "system/"+Name)
	if err == nil {
		return true, nil
	}
	// print returns 113 when the service is absent; bootout uses ESRCH (3).
	// Do not treat permission, timeout or other launchd errors as an absent job.
	if launchdExit(err, 113, 3) {
		return false, nil
	}
	return false, err
}

func stopLaunchd(ctx context.Context, command launchctlCommand) error {
	err := command(ctx, "bootout", "system/"+Name)
	// ESRCH means already removed; EINPROGRESS means an earlier bootout is
	// still draining the job. Both require the same unloaded-state check.
	if err != nil && !launchdExit(err, 3, 36) {
		return err
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		loaded, err := launchdLoaded(ctx, command)
		if err != nil {
			return err
		}
		if !loaded {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("launchd service did not unload: %w", ctx.Err())
		case <-tick.C:
		}
	}
}
func Inspect() (Status, error) {
	result := Status{Name: Name}
	_, err := os.Stat(plistPath)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Installed = true
	result.Running, err = launchdLoaded(context.Background(), launchctl)
	return result, err
}
func Uninstall() error {
	status, err := Inspect()
	if err != nil || !status.Installed {
		return err
	}
	if status.Running {
		if err = Stop(); err != nil {
			return err
		}
	}
	return os.Remove(plistPath)
}
func Run(ctx context.Context, agent func(context.Context) error) error { return agent(ctx) }
