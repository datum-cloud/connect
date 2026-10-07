package daemonservice

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
	"go.datum.net/datumctl-plugins/connect/internal/output"
)

// BootstrapCommand is optional: interactive serve/up invokes the same setup.
func BootstrapCommand() *cobra.Command {
	var executable string
	var upgrade bool
	cmd := &cobra.Command{
		Use: "install", Short: "Download, install, and start your local Connect daemon",
		Long: "Install the matching release daemon as a macOS or Linux user service and wait for readiness.\nThis does not log in, enroll a device, or share applications. When an existing\nuser service runs a different release, install upgrades it and verifies readiness.\nInteractive join, up, and serve do the same automatically. Use --executable for\na local build. For privileged or Windows services, use daemon install instead.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			baseURL, _ := cmd.Flags().GetString("daemon-url")
			if baseURL != "" && baseURL != connectapi.DefaultBaseURL {
				return fmt.Errorf("install configures only the default local daemon; omit --daemon-url")
			}
			if executable != "" && !filepath.IsAbs(executable) {
				return fmt.Errorf("--executable must be an absolute path")
			}
			timeout, _ := cmd.Flags().GetDuration("timeout")
			if timeout <= 0 {
				timeout = 30 * time.Second
			}
			installed, upgraded, err := EnsureCurrentUser(cmd.Context(), cmd.Root().Version, executable, timeout, cmd.ErrOrStderr(), upgrade)
			if err != nil {
				return err
			}
			if upgrade && !installed {
				return fmt.Errorf("Connect user service is not installed; run `datumctl connect install` first")
			}
			if installed {
				if upgraded {
					return output.Write(cmd, map[string]any{"status": "ready", "system": false, "upgraded": true}, "Connect daemon is upgraded and ready. Saved configuration and credentials are unchanged.\n")
				}
				if daemonAPIHealthy(cmd.Context(), connectapi.DefaultBaseURL) {
					return output.Write(cmd, map[string]any{"status": "ready", "system": false, "upgraded": false}, "Connect daemon is already installed and current.\n")
				}
				if err := bootstrapUser(cmd.Context(), cmd.Root().Version, executable, timeout, cmd.ErrOrStderr(), func(string) error { return nil }, false); err != nil {
					return err
				}
				return output.Write(cmd, map[string]any{"status": "ready", "system": false, "upgraded": false}, "Connect daemon is ready.\n")
			}
			client, err := connectapi.New(connectapi.DefaultBaseURL, "", min(timeout, 2*time.Second))
			if err != nil {
				return err
			}
			_, err = client.Request(cmd.Context(), http.MethodGet, "/v1/health", "", nil)
			if !errors.Is(err, syscall.ECONNREFUSED) {
				return fmt.Errorf("local daemon port is occupied or unavailable; left unchanged. Inspect datumctl connect daemon status before installing")
			}
			err = bootstrapUser(cmd.Context(), cmd.Root().Version, executable, timeout, cmd.ErrOrStderr(), func(string) error { return nil }, true)
			if err != nil {
				return err
			}
			return output.Write(cmd, map[string]any{"status": "ready", "system": false, "upgraded": false}, "Connect daemon is ready. Share an application: datumctl connect serve localhost:8080\n")
		},
	}
	cmd.Flags().StringVar(&executable, "executable", "", "Absolute path to a trusted local daemon instead of downloading")
	cmd.Flags().BoolVar(&upgrade, "upgrade", false, "Check and upgrade an existing user service (now the default)")
	return cmd
}
