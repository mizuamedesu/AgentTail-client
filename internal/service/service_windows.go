package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const Name = "AgentTail"

func connect() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(Name)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}
func Install(executable, directory string) error {
	if err := Validate(executable, directory); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	// CreateService supplies a default for ServiceType=0; UpdateConfig does
	// not. Keep the service type explicit so signed upgrades remain valid.
	config := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, DisplayName: "AgentTail encrypted virtual-IP network", Description: "Key-scoped WireGuard over ICE and Cloudflare TURN", StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, DelayedAutoStart: true, ServiceStartName: "LocalSystem", Dependencies: []string{"Tcpip"}}
	args := []string{"--state-dir", directory, "agent", "run"}
	s, err := m.OpenService(Name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		s, err = m.CreateService(Name, executable, config, args...)
	} else if err == nil {
		parts := []string{windows.EscapeArg(executable)}
		for _, arg := range args {
			parts = append(parts, windows.EscapeArg(arg))
		}
		config.BinaryPathName = strings.Join(parts, " ")
		err = s.UpdateConfig(config)
		if err != nil {
			err = fmt.Errorf("update Windows service configuration: %w", err)
		}
	}
	if err != nil {
		if s != nil {
			s.Close()
		}
		return err
	}
	defer s.Close()
	if err = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 86400); err != nil {
		return err
	}
	if err = s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Running {
		return nil
	}
	return s.Start()
}
func Start() error {
	m, s, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		return nil
	}
	return s.Start()
}
func Stop() error {
	m, s, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err = s.Control(svc.Stop); err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("AgentTail service did not stop within 20 seconds")
}
func Restart() error {
	if err := Stop(); err != nil {
		return err
	}
	return Start()
}
func Inspect() (Status, error) {
	result := Status{Name: Name}
	m, s, err := connect()
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer m.Disconnect()
	defer s.Close()
	result.Installed = true
	status, err := s.Query()
	result.Running = status.State == svc.Running
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
	m, s, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	return s.Delete()
}

type handler struct {
	ctx   context.Context
	agent func(context.Context) error
}

func (h handler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	changes <- svc.Status{State: svc.StartPending, WaitHint: 10000}
	done := make(chan error, 1)
	go func() { done <- h.agent(ctx) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending, WaitHint: 20000}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						return true, 1
					}
					return false, 0
				case <-time.After(18 * time.Second):
					return true, 2
				}
			}
		case <-h.ctx.Done():
			cancel()
			<-done
			return false, 0
		}
	}
}
func Run(ctx context.Context, agent func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return agent(ctx)
	}
	return svc.Run(Name, handler{ctx: ctx, agent: agent})
}
