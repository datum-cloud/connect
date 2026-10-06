package daemonservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"go.datum.net/datumctl-plugins/connect/internal/output"
)

// HelperCommand manages only the privileged adapter service, not the OIDC daemon.
func HelperCommand() *cobra.Command {
	root := &cobra.Command{Use: "helper", Short: "Manage the privileged peer-IP networking helper (macOS/Linux)", Long: "Manage the privileged networking helper for approved peer-IP interfaces.\nYour regular Connect daemon keeps your OIDC login and Connector identity.\nThe helper receives no cloud credentials. Installation requires administrator\napproval of exact interface settings for a non-root user. It does not enroll\na device or join a network. This preview supports macOS and Linux only."}
	root.AddCommand(helperAuthorizeCommand())
	descriptions := map[string]string{"install": "Install and start the networking helper", "uninstall": "Stop and uninstall the networking helper", "start": "Start the networking helper", "stop": "Stop the networking helper and release its interfaces", "status": "Show networking helper service status"}
	for _, action := range []string{"install", "uninstall", "start", "stop", "status"} {
		var uid uint32
		var executable, config string
		cmd := &cobra.Command{Use: action, Args: cobra.NoArgs, Short: descriptions[action], RunE: func(cmd *cobra.Command, _ []string) error {
			if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
				return fmt.Errorf("the networking helper currently supports macOS and Linux only")
			}
			if uid == 0 || uid == ^uint32(0) {
				return fmt.Errorf("pass --uid with the non-root user who runs Connect (run id -u in that user's terminal)")
			}
			if action != "status" {
				if err := requireSystemPrivileges(); err != nil {
					return fmt.Errorf("managing the networking helper requires administrator privileges; rerun this command with sudo (your regular Connect daemon stays unprivileged)")
				}
			}
			dir := helperStateDir(uid)
			socket := filepath.Join(dir, "helper.sock")
			if action == "install" {
				if !filepath.IsAbs(executable) || !filepath.IsAbs(config) {
					return fmt.Errorf("helper install requires absolute --executable and --config paths")
				}
				if err := validatePrivilegedExecutable(executable); err != nil {
					return err
				}
				info, err := os.Stat(executable)
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
					return fmt.Errorf("helper executable must be a regular executable file")
				}
			}
			cfg := helperServiceConfig(uid, executable)
			svc, err := service.New(nil, cfg)
			if err != nil {
				return err
			}
			if action == "install" {
				if _, err := svc.Status(); err == nil {
					return fmt.Errorf("networking helper is already installed; existing approvals were not changed")
				} else if !errors.Is(err, service.ErrNotInstalled) {
					return err
				}
				// Refuse existing state rather than overwriting an administrator's approvals.
				if err := validatePrivilegedExecutable(filepath.Dir(dir)); err != nil {
					return err
				}
				if err := os.Mkdir(dir, 0711); err != nil {
					return fmt.Errorf("create fresh helper state directory: %w", err)
				}
				if err := os.Chmod(dir, 0711); err != nil {
					return err
				}
				destination := filepath.Join(dir, "approvals.json")
				if err := copyPrivateFile(config, destination, 65536); err != nil {
					return err
				}
				data, err := os.ReadFile(destination)
				if err != nil {
					return err
				}
				var shape struct {
					AllowedUID uint32 `json:"allowed_uid"`
				}
				if json.Unmarshal(data, &shape) != nil || shape.AllowedUID != uid {
					return fmt.Errorf("helper approval allowed_uid must match --uid; service was not installed")
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				defer cancel()
				if err := exec.CommandContext(ctx, executable, "--check", "--config", destination).Run(); err != nil {
					return fmt.Errorf("helper rejected approval file; service was not installed: %w", err)
				}
				if err := svc.Install(); err != nil {
					return err
				}
				if err := svc.Start(); err != nil {
					return err
				}
				return output.Write(cmd, map[string]any{"action": "installed", "uid": uid, "socket": socket}, fmt.Sprintf("Installed networking helper for user %d.\nSocket: %s\nYour user daemon and OIDC credentials are unchanged.\n", uid, socket))
			}
			switch action {
			case "status":
				status, err := svc.Status()
				if err != nil {
					return err
				}
				label := "unknown"
				if status == service.StatusRunning {
					label = "running"
				} else if status == service.StatusStopped {
					label = "stopped"
				}
				return output.Write(cmd, map[string]any{"status": label, "uid": uid, "socket": socket}, fmt.Sprintf("Networking helper for user %d: %s\nSocket: %s\n", uid, label, socket))
			case "start":
				if err := svc.Start(); err != nil {
					return err
				}
				return output.Write(cmd, map[string]any{"action": "started", "uid": uid}, fmt.Sprintf("Started networking helper for user %d.\n", uid))
			case "stop":
				if err := svc.Stop(); err != nil {
					return err
				}
				return output.Write(cmd, map[string]any{"action": "stopped", "uid": uid}, fmt.Sprintf("Stopped networking helper for user %d. Its peer-IP interfaces are released.\n", uid))
			case "uninstall":
				if err := svc.Stop(); err != nil {
					return fmt.Errorf("stop helper before uninstalling: %w", err)
				}
				if err := svc.Uninstall(); err != nil {
					return err
				}
				return output.Write(cmd, map[string]any{"action": "uninstalled", "uid": uid, "state_dir": dir}, fmt.Sprintf("Uninstalled networking helper. Administrator approvals remain at %s.\n", dir))
			}
			return nil
		}}
		cmd.Flags().Uint32Var(&uid, "uid", 0, "Non-root user ID allowed to use this helper (id -u)")
		if action == "install" {
			cmd.Flags().StringVar(&executable, "executable", "", "Absolute root-owned path to datum-connect-network-helper")
			cmd.Flags().StringVar(&config, "config", "", "Approval JSON to copy into administrator-owned state")
		}
		root.AddCommand(cmd)
	}
	return root
}

func helperStateDir(uid uint32) string {
	base := "/var/lib"
	if runtime.GOOS == "darwin" {
		base = "/Library/PrivilegedHelperTools"
	}
	return filepath.Join(base, "datum-connect-network-"+strconv.FormatUint(uint64(uid), 10))
}

// helperExecutableDir keeps executable code out of mutable state directories.
// On SELinux systems, /var/lib is labeled var_lib_t and systemd cannot execute
// a helper stored there. Linux executables belong under /usr/libexec; approvals
// and the socket remain under /var/lib.
func helperExecutableDir(uid uint32) string {
	if runtime.GOOS == "linux" {
		return filepath.Join("/usr/libexec/datum-connect", strconv.FormatUint(uint64(uid), 10))
	}
	return helperStateDir(uid)
}

func helperServiceConfig(uid uint32, executable string) *service.Config {
	dir := helperStateDir(uid)
	return &service.Config{
		Name:        "datum-connect-network-helper-" + strconv.FormatUint(uint64(uid), 10),
		DisplayName: "Datum Connect networking helper",
		Description: "Owns only administrator-approved peer-IP interfaces; no cloud credentials",
		Executable:  executable,
		Arguments:   []string{"--config", filepath.Join(dir, "approvals.json"), "--socket", filepath.Join(dir, "helper.sock")},
		Option:      service.KeyValue{"UserService": false, "RunAtLoad": true, "KeepAlive": true, "LogOutput": true, "LogDirectory": dir},
	}
}
