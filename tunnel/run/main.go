package run

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/daemon"
	"go.datum.net/datumctl-plugins/connect/internal/state"
	"go.datum.net/datumctl-plugins/connect/internal/svcconfig"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "(internal) Run tunnel supervisor",
		Long: `Start the tunnel supervisor process. This is the internal entry point
used by the daemon background process (--detach). It is also called by
systemd/launchd service units in Phase 6.`,
		RunE: runRun,
	}
	cmd.Flags().String("name", "", "Tunnel name (required)")
	cmd.Flags().String("endpoint", "", "Local address to expose")
	cmd.Flags().String("label", "", "Display name")
	cmd.Flags().String("log-file", "", "Path for Rust debug log output")
	cmd.Flags().String("project", "", "Project ID (checked against persisted config)")
	cmd.Flags().String("session", "", "Service-account session name")
	cmd.Flags().Bool("yes", false, "Skip confirmation")
	return cmd
}

func runRun(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	endpoint, _ := cmd.Flags().GetString("endpoint")
	label, _ := cmd.Flags().GetString("label")
	logFile, _ := cmd.Flags().GetString("log-file")
	session, _ := cmd.Flags().GetString("session")
	yes, _ := cmd.Flags().GetBool("yes")

	// Load persisted config
	cfgPath := svcconfig.ConfigFilePath(name)
	svcCfg, err := svcconfig.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: load config for '%s': %v\n", name, err)
		os.Exit(1)
	}

	// Check --project mismatch (install-time project is authoritative for services)
	if projectFlag, _ := cmd.Flags().GetString("project"); projectFlag != "" && projectFlag != svcCfg.Project {
		fmt.Fprintf(os.Stderr, "Error: --project '%s' does not match installed project '%s'. Reinstall to change project.\n", projectFlag, svcCfg.Project)
		os.Exit(64)
	}

	// If --session provided, obtain token directly from credentials helper
	if session != "" {
		token, err := getTokenFromSession(session)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: get token: %v\n", err)
			os.Exit(1)
		}
		// Set DATUM_ACCESS_TOKEN and DATUM_SESSION in env for the supervisor
		os.Setenv("DATUM_ACCESS_TOKEN", token)
		os.Setenv("DATUM_SESSION", session)
	}

	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		os.Exit(64)
	}
	if endpoint == "" {
		fmt.Fprintln(os.Stderr, "Error: --endpoint is required")
		os.Exit(64)
	}

	// If --log-file empty, default to state log directory
	if logFile == "" {
		logFile = state.LogFilePath(name)
	}

	cfg := daemon.Config{
		Name:     name,
		Label:    label,
		Endpoint: endpoint,
		LogFile:  logFile,
		Yes:      yes,
	}

	ctx := context.Background()
	if err := daemon.RunSupervisor(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: %v\n", err)
		os.Exit(1)
	}
	return nil
}

// getTokenFromSession execs the credentials helper to obtain a token for the
// given session. Used when running as a systemd service (no parent datumctl).
func getTokenFromSession(session string) (string, error) {
	helper := os.Getenv("DATUM_CREDENTIALS_HELPER")
	if helper == "" {
		return "", fmt.Errorf("DATUM_CREDENTIALS_HELPER not set")
	}
	out, err := exec.Command(helper, "auth", "get-token", "--session", session).Output()
	if err != nil {
		return "", fmt.Errorf("credentials helper: %w", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("empty token from credentials helper")
	}
	return token, nil
}
