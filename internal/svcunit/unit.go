// Package svcunit provides service unit management via kardianos/service.
//
// Manages user-scoped systemd units for Datum Connect tunnels.
// All operations use kardianos/service which delegates to systemctl --user.
package svcunit

import (
	"fmt"
	"os/exec"

	"github.com/kardianos/service"

	"go.datum.net/datumctl-plugins/connect/internal/svcconfig"
)

// ServiceName returns the kardianos/service name for a tunnel.
func ServiceName(tunnelName string) string {
	return "datumctl-connect-" + tunnelName
}

// ServiceArgs builds the CLI arguments for the tunnel run command.
func ServiceArgs(cfg svcconfig.TunnelConfig) []string {
	args := []string{"tunnel", "run", "--name", cfg.Name, "--endpoint", cfg.Endpoint}
	if cfg.Label != "" {
		args = append(args, "--label", cfg.Label)
	}
	if cfg.Session != "" {
		args = append(args, "--session", cfg.Session)
	}
	args = append(args, "--yes")
	return args
}

// Install registers a user-scoped systemd unit via kardianos/service.
// Does NOT start the service.
func Install(cfg svcconfig.TunnelConfig, binaryPath string) error {
	svc, err := newService(cfg, binaryPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	if err := svc.Install(); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	return nil
}

// Uninstall removes the systemd unit and any running instance.
func Uninstall(tunnelName string, binaryPath string) error {
	svc, err := newService(svcconfig.TunnelConfig{Name: tunnelName}, binaryPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	// Stop first, then uninstall
	_ = svc.Stop()
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("uninstall service: %w", err)
	}
	return nil
}

// Start starts the installed service via systemctl --user.
func Start(tunnelName string, binaryPath string) error {
	svc, err := newService(svcconfig.TunnelConfig{Name: tunnelName}, binaryPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	return svc.Start()
}

// Stop stops the installed service via systemctl --user.
func Stop(tunnelName string, binaryPath string) error {
	svc, err := newService(svcconfig.TunnelConfig{Name: tunnelName}, binaryPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	return svc.Stop()
}

// Status returns the service status.
func Status(tunnelName string, binaryPath string) (string, error) {
	svc, err := newService(svcconfig.TunnelConfig{Name: tunnelName}, binaryPath)
	if err != nil {
		return "", fmt.Errorf("create service: %w", err)
	}
	st, err := svc.Status()
	if err != nil {
		return "", fmt.Errorf("get status: %w", err)
	}
	return statusString(st), nil
}

// newService creates a kardianos/service instance for a tunnel.
func newService(cfg svcconfig.TunnelConfig, binaryPath string) (service.Service, error) {
	svcConfig := &service.Config{
		Name:        ServiceName(cfg.Name),
		DisplayName: fmt.Sprintf("Datum Connect Tunnel: %s", cfg.Name),
		Description: fmt.Sprintf("Datum Connect tunnel to %s (%s)", cfg.Endpoint, cfg.Name),
		Executable:  binaryPath,
		Arguments:   ServiceArgs(cfg),
		Dependencies: []string{
			"After=network-online.target",
			"Wants=network-online.target",
		},
		Option: service.KeyValue{
			"UserService": true,
			"Restart":     "on-failure",
			"RestartSec":  "5",
		},
	}

	svc, err := service.New(nil, svcConfig)
	if err != nil {
		return nil, fmt.Errorf("new service: %w", err)
	}
	return svc, nil
}

func statusString(s service.Status) string {
	switch s {
	case service.StatusRunning:
		return "Running"
	case service.StatusStopped:
		return "Stopped"
	default:
		return "Unknown"
	}
}

// binaryPath resolves the path to the current plugin binary for service use.
func binaryPath() string {
	path, err := exec.LookPath("datumctl-connect")
	if err == nil {
		return path
	}
	return "datumctl-connect"
}
