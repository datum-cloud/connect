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
	cmd := &cobra.Command{
		Use: "install", Short: "Download, install, and start your local Connect daemon",
		Long: "Install the matching release daemon as a macOS or Linux user service and wait for readiness.\nThis does not log in, enroll a device, or share applications. Existing services\nare left unchanged. Interactive serve handles this setup automatically.\nUse --executable for an explicit local build or offline installation.\nFor privileged or Windows services, use daemon install instead.",
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
			return output.Write(cmd, map[string]any{"status": "ready", "system": false}, "Connect daemon is ready. Share an application: datumctl connect serve localhost:8080\n")
		},
	}
	cmd.Flags().StringVar(&executable, "executable", "", "Absolute path to a trusted local daemon instead of downloading")
	return cmd
}
