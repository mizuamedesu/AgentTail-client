// SPDX-License-Identifier: GPL-3.0-or-later

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mizuamedesu/AgentTail-client/internal/localstate"
	"github.com/mizuamedesu/AgentTail-client/internal/secrets"
	"golang.org/x/sys/unix"
)

const initMarker = "#!/bin/sh\n# AgentTail managed Linux service\n"
const legacyInitMarker = "#!/bin/sh\n# AgentTail managed NanoKVM service\n"
const maxFailureOutput = 4096

var applianceService = busyboxService{
	configDir:  "/etc/agenttail-service",
	runtimeDir: "/var/run/agenttail-service",
	initPath:   "/etc/init.d/S99agenttail",
}

func Supervise(ctx context.Context) error { return applianceService.supervise(ctx) }

// Retain only the tail of stderr from one child, never a growing log on the SD
// card. exec.Cmd finishes copying this writer before Wait returns.
type failureOutput struct{ data []byte }

func (w *failureOutput) Write(p []byte) (int, error) {
	n := len(p)
	if n >= maxFailureOutput {
		w.data = append(w.data[:0], p[n-maxFailureOutput:]...)
	} else {
		if len(w.data)+n > maxFailureOutput {
			w.data = w.data[len(w.data)+n-maxFailureOutput:]
		}
		w.data = append(w.data, p...)
	}
	return n, nil
}

// Paths are fixed in production; tests exercise this adapter in private dirs.
type busyboxService struct{ configDir, runtimeDir, initPath string }
type busyboxConfig struct{ Executable, Directory string }
type busyboxPID struct {
	PID     int
	Started string
}

func (b busyboxService) failurePath() string { return filepath.Join(b.runtimeDir, "last-error.txt") }

func (b busyboxService) recordFailure(message string) error {
	if _, err := secrets.New(b.runtimeDir); err != nil {
		return err
	}
	if len(message) > maxFailureOutput {
		message = message[:512] + "\n[output truncated]\n" + message[len(message)-3072:]
	}
	return writeMode(b.failurePath(), []byte(strings.TrimSpace(message)+"\n"), 0600)
}

func (b busyboxService) lastFailure() (string, error) {
	f, err := os.Open(b.failurePath())
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFailureOutput+1))
	return strings.TrimSpace(string(data)), err
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (b busyboxService) script(c busyboxConfig) string {
	return initMarker + "case \"$1\" in\n  start|stop|restart|status) exec " + shellQuote(c.Executable) + " --state-dir " + shellQuote(c.Directory) + " service \"$1\" ;;\n  *) echo 'Usage: $0 {start|stop|restart|status}' >&2; exit 2 ;;\nesac\n"
}
func (b busyboxService) prepare() error {
	for _, path := range []string{b.configDir, b.runtimeDir} {
		if _, err := secrets.New(path); err != nil {
			return err
		}
	}
	return nil
}
func (b busyboxService) config() (busyboxConfig, error) {
	var c busyboxConfig
	if err := b.prepare(); err != nil {
		return c, err
	}
	data, err := os.ReadFile(filepath.Join(b.configDir, "config.json"))
	if err != nil {
		return c, err
	}
	if json.Unmarshal(data, &c) != nil {
		return c, errors.New("invalid Linux service configuration")
	}
	return c, Validate(c.Executable, c.Directory)
}
func (b busyboxService) lock() (func(), error) {
	if err := b.prepare(); err != nil {
		return nil, err
	}
	return localstate.OperationLock(filepath.Join(b.runtimeDir, "manager.lock"))
}
func (b busyboxService) install(executable, directory string) error {
	if err := Validate(executable, directory); err != nil {
		return err
	}
	if _, err := secrets.New(directory); err != nil {
		return err
	}
	unlock, err := b.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if data, e := os.ReadFile(b.initPath); e == nil && !strings.HasPrefix(string(data), initMarker) && !strings.HasPrefix(string(data), legacyInitMarker) {
		return errors.New("Linux service script is not managed by AgentTail")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	c := busyboxConfig{executable, directory}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err = write(filepath.Join(b.configDir, "config.json"), data); err != nil {
		return err
	}
	if err = write(b.initPath, []byte(b.script(c))); err != nil {
		return err
	}
	if err = os.Chmod(b.initPath, 0755); err != nil {
		return err
	}
	return b.startLocked()
}

// Match the kernel start time as well as the PID, so a stale pidfile can never
// stop an unrelated process after PID reuse. FindProcess pins a pidfd on Linux.
func processStart(pid int) (string, error) {
	// Open relative to procfs so the process record is the kernel's record,
	// including when a user-space CPU emulator synthesizes /proc/self/stat.
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		return "", err
	}
	defer proc.Close()
	f, err := proc.Open(fmt.Sprintf("%d/stat", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", err
	}
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 {
		return "", errors.New("invalid process identity")
	}
	fields := strings.Fields(string(data[i+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return "", os.ErrProcessDone
	}
	return fields[19], nil
}
func (b busyboxService) process() (*os.Process, error) {
	data, err := os.ReadFile(filepath.Join(b.runtimeDir, "supervisor.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p busyboxPID
	if json.Unmarshal(data, &p) != nil || p.PID <= 1 || p.Started == "" {
		return nil, errors.New("invalid service process record")
	}
	process, err := os.FindProcess(p.PID)
	if err != nil {
		return nil, err
	}
	started, err := processStart(p.PID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrProcessDone) || err == nil && started != p.Started {
		process.Release()
		return nil, nil
	}
	if err != nil {
		process.Release()
		return nil, err
	}
	return process, nil
}
func (b busyboxService) inspect() (Status, error) {
	status := Status{Name: "agenttail"}
	if _, err := b.config(); errors.Is(err, os.ErrNotExist) {
		return status, nil
	} else if err != nil {
		return status, err
	}
	status.Installed = true
	p, err := b.process()
	if p != nil {
		status.Running = true
		p.Release()
	}
	if err == nil {
		status.LastFailure, err = b.lastFailure()
	}
	return status, err
}
func (b busyboxService) start() error {
	unlock, err := b.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return b.startLocked()
}
func (b busyboxService) startLocked() error {
	c, err := b.config()
	if err != nil {
		return err
	}
	p, err := b.process()
	if err != nil {
		return err
	}
	if p != nil {
		p.Release()
		return nil
	}
	if err = os.Remove(b.failurePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cmd := exec.Command(c.Executable, "--state-dir", c.Directory, "agent", "supervise")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		p, err = b.process()
		if err != nil {
			return err
		}
		if p != nil {
			found := p.Pid == pid
			p.Release()
			if found {
				return nil
			}
		}
		select {
		case exit := <-done:
			failure, _ := b.lastFailure()
			return fmt.Errorf("Linux supervisor exited before startup: %v; %s", exit, failure)
		case <-time.After(50 * time.Millisecond):
		}
	}
	return errors.New("Linux supervisor did not start")
}
func (b busyboxService) stop() error {
	unlock, err := b.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return b.stopLocked()
}
func (b busyboxService) stopLocked() error {
	p, err := b.process()
	if err != nil || p == nil {
		return err
	}
	defer p.Release()
	if err = p.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		current, err := b.process()
		if err != nil {
			return err
		}
		if current == nil {
			return nil
		}
		current.Release()
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("Linux supervisor did not stop; installation retained")
}
func (b busyboxService) uninstall() error {
	unlock, err := b.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err = b.stopLocked(); err != nil {
		return err
	}
	for _, path := range []string{b.initPath, filepath.Join(b.configDir, "config.json")} {
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (b busyboxService) supervise(ctx context.Context) (result error) {
	defer func() {
		if result != nil {
			_ = b.recordFailure("supervisor failed: " + result.Error())
		}
	}()
	// Pdeathsig follows the thread that created the child. Keep that thread
	// alive for the whole supervisor lifetime, including restarts.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	c, err := b.config()
	if err != nil {
		return err
	}
	unlock, err := localstate.OperationLock(filepath.Join(b.runtimeDir, "supervisor.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	started, err := processStart(os.Getpid())
	if err != nil {
		return err
	}
	data, err := json.Marshal(busyboxPID{os.Getpid(), started})
	if err != nil {
		return err
	}
	pidfile := filepath.Join(b.runtimeDir, "supervisor.json")
	if err = write(pidfile, data); err != nil {
		return err
	}
	defer os.Remove(pidfile)
	for ctx.Err() == nil {
		cmd := exec.Command(c.Executable, "--state-dir", c.Directory, "agent", "run")
		output := &failureOutput{}
		cmd.Stderr = output
		cmd.Env = os.Environ()
		if os.Getenv("GOMEMLIMIT") == "" {
			cmd.Env = append(cmd.Env, "GOMEMLIMIT=64MiB")
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		if err = cmd.Start(); err == nil {
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err = <-done:
			case <-ctx.Done():
				_ = cmd.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					_ = cmd.Process.Kill()
					<-done
				}
				return nil
			}
		}
		message := fmt.Sprintf("agent run failed: %v", err)
		if err == nil {
			message = "agent run exited unexpectedly with status 0"
		}
		if len(output.data) > 0 {
			message += "\n" + string(output.data)
		}
		_ = b.recordFailure(message)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}
