// Package daemonservice manages the Connect OS service registration. The
// existing service label remains datum-connect-daemon for upgrade compatibility.
package daemonservice

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
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
	"go.datum.net/datumctl-plugins/connect/internal/output"
	"go.datum.net/datumctl-plugins/connect/internal/state"
)

const serviceName = "datum-connect-daemon" // Keep the registered label stable across binary renames.

// DiscoverExecutable finds the daemon beside the plugin or in PATH.
func DiscoverExecutable() (string, error) { return daemonExecutable("") }

// SystemSetupTokenPath is the privileged setup token created by a system daemon.
func SystemSetupTokenPath() string {
	return filepath.Join(serviceStateDir(true), "daemon_auth", "setup.token")
}

type installOptions struct {
	system          bool
	credentialsFile string
	localIPConfig   string
	port            uint16
	executable      string
}

func InstallCommand() *cobra.Command {
	o := &installOptions{}
	cmd := &cobra.Command{Use: "install", Short: "Install the Datum Connect daemon as an OS service", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return install(cmd, *o)
	}}
	addScopeFlag(cmd, &o.system)
	cmd.Flags().StringVar(&o.credentialsFile, "credentials-file", "", "Credential JSON to copy into service-owned state")
	cmd.Flags().StringVar(&o.localIPConfig, "local-ip-config", "", "Absolute path to CONNECT-IP approvals (system daemon or approved networking helper)")
	cmd.Flags().Uint16Var(&o.port, "port", 47780, "Loopback HTTP port")
	cmd.Flags().StringVar(&o.executable, "executable", "", "Path to datum-connectd (defaults to PATH lookup)")
	return cmd
}

func UninstallCommand() *cobra.Command {
	return lifecycleCommand("uninstall", "Uninstall the Datum Connect daemon service", func(s service.Service) error { return s.Uninstall() })
}
func StartCommand() *cobra.Command {
	return lifecycleCommand("start", "Start the Datum Connect daemon service", func(s service.Service) error { return s.Start() })
}
func StopCommand() *cobra.Command {
	return lifecycleCommand("stop", "Stop the Datum Connect daemon service", func(s service.Service) error { return s.Stop() })
}

func StatusCommand() *cobra.Command {
	var system bool
	cmd := &cobra.Command{Use: "status", Short: "Show the OS service status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validatePlatformScope(system); err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			if err := requireSystemPrivileges(); err != nil {
				return err
			}
		}
		svc, _, err := makeService(system, "", 47780, "", "")
		if err != nil {
			return err
		}
		status, err := statusService(svc, system)
		notInstalled := errors.Is(err, service.ErrNotInstalled)
		if err != nil && !notInstalled {
			return fmt.Errorf("daemon service status: %w", err)
		}
		label := "not installed"
		if !notInstalled {
			label = "unknown"
			switch status {
			case service.StatusRunning:
				label = "running"
			case service.StatusStopped:
				label = "stopped"
			}
		}
		baseURL, _ := cmd.InheritedFlags().GetString("daemon-url")
		apiStatus := "unreachable"
		if daemonAPIHealthy(cmd.Context(), baseURL) {
			apiStatus = "reachable"
		}
		human := fmt.Sprintf("Connect daemon service is %s (%s).\nConnect daemon API is %s.\n", label, scopeLabel(system), apiStatus)
		if label == "stopped" && apiStatus == "reachable" {
			human += "The API is responding even though the service manager reports it stopped; check for a manually started daemon or stale service-manager state.\n"
		} else if label == "not installed" && apiStatus == "reachable" {
			human += "The API is responding outside the managed daemon service.\n"
		}
		if label == "stopped" {
			human += "Start: datumctl connect daemon start" + scopeFlag(system) + "\n"
		} else if label == "not installed" {
			human += "Install: datumctl connect daemon install" + scopeFlag(system) + "\n"
		}
		return output.Write(cmd, map[string]any{"service": serviceName, "status": label, "api_status": apiStatus, "system": system}, human)
	}}
	addScopeFlag(cmd, &system)
	return cmd
}

// statusService uses launchctl's structured job report on macOS. kardianos/service
// parses `launchctl list`, which can omit a PID for a live job in some launchd
// contexts and then incorrectly reports an installed LaunchAgent as stopped.
func statusService(svc service.Service, system bool) (service.Status, error) {
	if runtime.GOOS != "darwin" {
		return svc.Status()
	}
	domain := fmt.Sprintf("gui/%d/%s", os.Getuid(), serviceName)
	if system {
		domain = "system/" + serviceName
	}
	output, err := exec.Command("launchctl", "print", domain).CombinedOutput()
	if err != nil {
		message := string(output)
		if strings.Contains(message, "Could not find service") || strings.Contains(message, "Service not found") {
			return svc.Status()
		}
		return service.StatusUnknown, fmt.Errorf("launchctl print %s: %w: %s", domain, err, strings.TrimSpace(message))
	}
	if launchdJobRunning(string(output)) {
		return service.StatusRunning, nil
	}
	return service.StatusStopped, nil
}

func launchdJobRunning(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pid = ") && strings.TrimPrefix(line, "pid = ") != "0" {
			return true
		}
	}
	return false
}

func daemonAPIHealthy(ctx context.Context, baseURL string) bool {
	client, err := connectapi.New(baseURL, "", 500*time.Millisecond)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
	defer cancel()
	data, err := client.Request(ctx, "GET", "/v1/health", "", nil)
	if err != nil {
		return false
	}
	var health struct {
		Status string `json:"status"`
	}
	return json.Unmarshal(data, &health) == nil && health.Status == "ok"
}

func lifecycleCommand(use, short string, action func(service.Service) error) *cobra.Command {
	var system bool
	cmd := &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validatePlatformScope(system); err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			if err := requireSystemPrivileges(); err != nil {
				return err
			}
		}
		svc, _, err := makeService(system, "", 47780, "", "")
		if err != nil {
			return err
		}
		actionTimeout := time.Duration(0)
		if runtime.GOOS == "windows" && use == "stop" {
			actionTimeout = 40 * time.Second
		}
		if err := runServiceAction(cmd.Context(), svc, action, actionTimeout); err != nil {
			if errors.Is(err, service.ErrNotInstalled) {
				return fmt.Errorf("Connect daemon service is not installed (%s).\nInstall: datumctl connect daemon install%s", scopeLabel(system), scopeFlag(system))
			}
			return fmt.Errorf("daemon service %s: %w", use, err)
		}
		human := ""
		switch use {
		case "start":
			baseURL, _ := cmd.Flags().GetString("daemon-url")
			timeout, _ := cmd.Flags().GetDuration("timeout")
			if timeout <= 0 {
				timeout = 30 * time.Second
			}
			if err := waitReady(cmd.Context(), baseURL, timeout); err != nil {
				return fmt.Errorf("service start was requested, but the daemon is not ready: %w\nCheck `datumctl connect daemon status%s` and the daemon log at %s. If installed with a custom port, pass --daemon-url http://127.0.0.1:PORT", err, scopeFlag(system), filepath.Join(serviceStateDir(system), "daemon.log"))
			}
			human = "Connect daemon is running and reachable.\n"
		case "stop":
			human = "Requested Connect daemon service stop. Saved configuration is preserved.\n"
		case "uninstall":
			human = "Connect daemon service is uninstalled. Saved configuration and credentials are preserved.\n"
		}
		return output.Write(cmd, map[string]any{"service": serviceName, "action": use, "system": system}, human)
	}}
	addScopeFlag(cmd, &system)
	return cmd
}

func runServiceAction(ctx context.Context, svc service.Service, action func(service.Service) error, timeout time.Duration) error {
	if timeout <= 0 {
		return action(svc)
	}
	result := make(chan error, 1)
	go func() { result <- action(svc) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("service manager did not complete the operation within %s; check service status and %s", timeout, filepath.Join(serviceStateDir(true), "daemon.log"))
	}
}

func addScopeFlag(cmd *cobra.Command, target *bool) {
	cmd.Flags().BoolVar(target, "system", false, "Manage a system service instead of the current user's service")
}

func install(cmd *cobra.Command, o installOptions) error {
	if err := validatePlatformScope(o.system); err != nil {
		return err
	}
	if o.system {
		if err := requireSystemPrivileges(); err != nil {
			return err
		}
	}
	if runtime.GOOS == "windows" && o.credentialsFile == "" {
		return fmt.Errorf("the Windows system service cannot use the interactive datumctl login helper; pass --credentials-file with renewable Connector or service-account credentials")
	}
	localIPConfig, err := validateLocalIPConfig(o.localIPConfig, o.system, o.credentialsFile != "")
	if err != nil {
		return err
	}
	executable, err := daemonExecutable(o.executable)
	if err != nil {
		return err
	}
	if o.system {
		if err := validatePrivilegedExecutable(executable); err != nil {
			return err
		}
	}
	stateDir := serviceStateDir(o.system)
	credentialCopy := ""
	if o.credentialsFile != "" {
		credentialCopy = filepath.Join(stateDir, "credentials.json")
	}
	serviceLocalIPConfig := ""
	if localIPConfig != "" {
		serviceLocalIPConfig = filepath.Join(stateDir, "local-ip.json")
	}
	svc, cfg, err := makeService(o.system, executable, o.port, credentialCopy, serviceLocalIPConfig)
	if err != nil {
		return err
	}
	if err := verifyConfig(cfg, o.system); err != nil {
		return fmt.Errorf("refuse invalid service config: %w", err)
	}
	if runtime.GOOS == "windows" {
		if _, err := svc.Status(); err == nil {
			return fmt.Errorf("Connect daemon service is already installed; uninstall it before reinstalling so existing credentials and configuration are not overwritten")
		} else if !errors.Is(err, service.ErrNotInstalled) {
			return fmt.Errorf("check existing daemon service before install: %w", err)
		}
	}
	if err := secureServiceState(stateDir); err != nil {
		return fmt.Errorf("create daemon state directory: %w", err)
	}
	if o.credentialsFile != "" {
		if err := copyCredential(o.credentialsFile, credentialCopy); err != nil {
			return err
		}
	}
	if localIPConfig != "" {
		if err := copyPrivateFile(localIPConfig, serviceLocalIPConfig, 4<<20); err != nil {
			return fmt.Errorf("copy local IP config: %w", err)
		}
	}
	if err := svc.Install(); err != nil {
		return fmt.Errorf("install daemon service: %w", err)
	}
	start := "datumctl connect daemon start" + scopeFlag(o.system)
	if o.port != 47780 {
		start += fmt.Sprintf(" --daemon-url http://127.0.0.1:%d", o.port)
	}
	human := fmt.Sprintf("Installed Connect daemon service (%s).\nState and logs: %s\nNext: %s\n", scopeLabel(o.system), stateDir, start)
	return output.Write(cmd, map[string]any{"service": serviceName, "action": "installed", "system": o.system, "state_dir": stateDir, "local_ip_config": serviceLocalIPConfig}, human)
}

func validateLocalIPConfig(value string, system, hasCredentials bool) (string, error) {
	if value == "" {
		return "", nil
	}
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("--local-ip-config must be an absolute path so the service can find it")
	}
	clean := filepath.Clean(value)
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("local IP config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("local IP config %s must be a regular file", clean)
	}
	if !system {
		if info.Size() > 4<<20 {
			return "", fmt.Errorf("local IP config exceeds 4 MiB")
		}
		file, err := os.Open(clean)
		if err != nil {
			return "", err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
		if err != nil {
			return "", err
		}
		var shape struct {
			NetworkHelper string            `json:"network_helper"`
			Bindings      []json.RawMessage `json:"bindings"`
			Peers         []json.RawMessage `json:"peer_bindings"`
		}
		if (runtime.GOOS != "darwin" && runtime.GOOS != "linux") || len(data) > 4<<20 || json.Unmarshal(data, &shape) != nil || !filepath.IsAbs(shape.NetworkHelper) || len(shape.Bindings) != 0 || len(shape.Peers) == 0 {
			return "", fmt.Errorf("user CONNECT-IP requires network_helper with approved peer_bindings; install the networking helper first, or use a system daemon with credentials")
		}
	}
	if system && runtime.GOOS == "darwin" && !hasCredentials {
		return "", fmt.Errorf("a macOS system service with --local-ip-config cannot use the current user's datumctl login; also pass --credentials-file with service-account credentials. For unprivileged L4 serve/dial with OIDC, omit --system and --local-ip-config")
	}
	return clean, nil
}

func scopeLabel(system bool) string {
	if system {
		return "system"
	}
	return "current user"
}

func scopeFlag(system bool) string {
	if system {
		return " --system"
	}
	return ""
}

// waitReady waits for the daemon API, not just the OS service manager's launch
// acknowledgement. It does not imply that a project or cloud gateway is ready.
func waitReady(ctx context.Context, baseURL string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := connectapi.New(baseURL, "", 500*time.Millisecond)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := client.Request(ctx, "GET", "/v1/health", "", nil)
		if err == nil {
			var health struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(data, &health) == nil && health.Status == "ok" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("health check did not succeed within %s", timeout)
		case <-ticker.C:
		}
	}
}

func validatePlatformScope(system bool) error {
	switch runtime.GOOS {
	case "windows":
		if !system {
			return fmt.Errorf("Windows supports only a system daemon service; add --system and run from an elevated terminal")
		}
	case "darwin":
		// launchd supports both LaunchAgents (user) and LaunchDaemons (system).
	case "linux":
		if !system && service.Platform() != "linux-systemd" {
			return fmt.Errorf("user services require systemd; detected %s (use --system only if a system service is intended)", service.Platform())
		}
	default:
		return fmt.Errorf("daemon service management is unsupported on %s; run datum-connectd directly", runtime.GOOS)
	}
	return nil
}

func daemonExecutable(explicit string) (string, error) {
	if explicit == "" {
		if self, err := os.Executable(); err == nil {
			name := "datum-connectd"
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			adjacent := filepath.Join(filepath.Dir(self), name)
			if info, statErr := os.Stat(adjacent); statErr == nil && !info.IsDir() {
				explicit = adjacent
			}
		}
		if explicit == "" {
			var err error
			explicit, err = exec.LookPath("datum-connectd")
			if err != nil {
				return "", fmt.Errorf("find datum-connectd next to the plugin or in PATH: %w", err)
			}
		}
	}
	abs, err := filepath.Abs(explicit)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("daemon executable: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("daemon executable %s is a directory", abs)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0) {
		return "", fmt.Errorf("daemon executable %s must be a regular executable file", abs)
	}
	return abs, nil
}

func serviceStateDir(system bool) string {
	if !system {
		return state.DaemonDir()
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(windowsProgramData(), "Datum", "Connect")
	case "darwin":
		return filepath.Join(string(filepath.Separator), "Library", "Application Support", "Datum Connect")
	default:
		return filepath.Join(string(filepath.Separator), "var", "lib", "datum-connect")
	}
}

func copyCredential(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open credentials file: %w", err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat credentials file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("credentials file %s is a directory", source)
	}
	if info.Size() > 4<<20 {
		return fmt.Errorf("credentials file exceeds 4 MiB")
	}
	var shape struct {
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
		ClientID     string `json:"client_id"`
		RefreshToken string `json:"refresh_token"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
	}
	decoder := json.NewDecoder(io.LimitReader(in, 4<<20))
	if err := decoder.Decode(&shape); err != nil {
		return fmt.Errorf("parse credentials file: %w", err)
	}
	switch shape.Type {
	case "connector":
		if shape.ProjectID == "" || shape.ClientID == "" || shape.RefreshToken == "" {
			return fmt.Errorf("connector credentials require project_id, client_id, and refresh_token")
		}
	case "datum_service_account":
		if shape.ProjectID == "" || shape.ClientID == "" || shape.PrivateKey == "" || shape.ClientEmail == "" {
			return fmt.Errorf("service-account credentials require project_id, client_id, private_key, and client_email")
		}
	default:
		return fmt.Errorf("unsupported credentials type %q", shape.Type)
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind credentials file: %w", err)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(destination), ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("create service credentials: %w", err)
	}
	tmp := tmpFile.Name()
	out := tmpFile
	if err := securePrivateFile(tmp); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("secure service credentials: %w", err)
	}
	_, copyErr := io.Copy(out, io.LimitReader(in, 4<<20))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("copy service credentials: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close service credentials: %w", closeErr)
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("secure service credentials: %w", err)
	}
	if err := os.Rename(tmp, destination); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("store service credentials: %w", err)
	}
	return nil
}

func copyPrivateFile(source, destination string, limit int64) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return fmt.Errorf("source must be a regular file no larger than %d bytes", limit)
	}
	out, err := os.CreateTemp(filepath.Dir(destination), ".private-*.tmp")
	if err != nil {
		return err
	}
	tmp := out.Name()
	defer os.Remove(tmp)
	if err := securePrivateFile(tmp); err != nil {
		_ = out.Close()
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(in, limit+1))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, destination)
}

// makeService builds a native kardianos service. An empty executable is used
// for lifecycle commands, where the installed service definition is authoritative.
func makeService(system bool, executable string, port uint16, credentials, localIPConfig string) (service.Service, *service.Config, error) {
	if executable == "" {
		executable = serviceName
	}
	stateDir := serviceStateDir(system)
	args := []string{
		"--repo", stateDir,
		"--port", fmt.Sprint(port),
		"--log-file", filepath.Join(stateDir, "daemon.log"),
	}
	if credentials != "" {
		args = append(args, "--credentials-file", credentials)
	}
	if localIPConfig != "" {
		args = append(args, "--local-ip-config", localIPConfig)
	}
	if runtime.GOOS == "windows" {
		args = append(args, "--windows-service")
	}
	cfg := &service.Config{
		Name: serviceName, DisplayName: "Datum Connect Daemon", Description: "Local Datum Connect networking daemon",
		Executable: executable, Arguments: args,
		Option: service.KeyValue{"UserService": !system},
	}
	if runtime.GOOS == "linux" {
		cfg.Dependencies = []string{"After=network-online.target", "Wants=network-online.target"}
		cfg.Option["Restart"] = "on-failure"
		cfg.Option["RestartSec"] = "5"
	}
	svc, err := service.New(nil, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create daemon service: %w", err)
	}
	return svc, cfg, nil
}

func verifyConfig(cfg *service.Config, system bool) error {
	if cfg.Name != serviceName {
		return fmt.Errorf("unexpected service name %q", cfg.Name)
	}
	if !filepath.IsAbs(cfg.Executable) {
		return fmt.Errorf("daemon executable must be absolute")
	}
	if len(cfg.Arguments) < 6 || cfg.Arguments[0] != "--repo" || cfg.Arguments[2] != "--port" || cfg.Arguments[4] != "--log-file" {
		return fmt.Errorf("missing explicit state, port, or log arguments")
	}
	userService, ok := cfg.Option["UserService"].(bool)
	if !ok || userService == system {
		return fmt.Errorf("service scope does not match --system")
	}
	return nil
}
