package run

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/daemon"
	"go.datum.net/datumctl-plugins/connect/internal/state"
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
	cmd.Flags().Bool("yes", false, "Skip confirmation")
	return cmd
}

func runRun(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	endpoint, _ := cmd.Flags().GetString("endpoint")
	label, _ := cmd.Flags().GetString("label")
	logFile, _ := cmd.Flags().GetString("log-file")
	yes, _ := cmd.Flags().GetBool("yes")

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
