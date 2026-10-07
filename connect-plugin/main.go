package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.datum.net/datumctl-plugins/connect/commands"
	"go.datum.net/datumctl-plugins/connect/internal/daemonservice"
	"go.datum.net/datumctl/plugin"
)

// Overridden at build time via -ldflags "-X main.version=vX.Y.Z".
// See Taskfile.yaml and .goreleaser.yaml.
var version = "v0.1.0-dev"

func main() {
	// Serve manifest before cobra parses anything
	m := plugin.Manifest{
		Name:        "connect",
		Version:     version,
		Description: "Connect devices and expose services through Datum Connect",
		APIVersion:  1,
	}
	plugin.ServeManifest(m)

	// Create root command with pre-wired flags
	cmd := plugin.NewRootCmd("connect", "Manage Datum Connect")
	cmd.Version = version
	cmd.Args = cobra.NoArgs
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.Long, cmd.Example = rootHelp(runtime.GOOS, daemonservice.SystemSetupTokenPath())
	cmd.RunE = func(cmd *cobra.Command, _ []string) error { return cmd.Help() }
	commands.Add(cmd)
	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the CLI and daemon versions",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "datumctl-connect %s\n", version)
			if daemonPath, err := daemonservice.DiscoverExecutable(); err == nil {
				ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, daemonPath, "--version").Output()
				if err == nil {
					fmt.Fprintln(cmd.OutOrStdout(), strings.TrimSpace(string(out)))
				}
			}
		},
	})

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func rootHelp(goos, setupToken string) (string, string) {
	base := "Connect your device, expose a local service, or open a port to another Connector.\nServices are private unless you explicitly use --public."
	operations := "\n\n  # Use the project selected in your datumctl context, or pass --project PROJECT\n  datumctl connect serve localhost:8080 --public\n  datumctl connect serve localhost:22 --allow TEAMMATE_CONNECTOR\n  datumctl connect dial SERVER_CONNECTOR:22 --bind 2222\n  datumctl connect status"
	if goos == "windows" {
		long := base + "\n\nWindows runs Connect as a LocalSystem service and requires renewable file credentials\n(Connector refresh-token or service-account JSON). Interactive datumctl OIDC is not\navailable to the Windows service. Pass the protected system setup token to\nadministrative commands with --token-file."
		example := "  # First-time Windows setup (run from elevated PowerShell)\n  datumctl connect daemon install --system --credentials-file C:\\secure\\service-account.json\n  datumctl connect daemon start --system\n  datumctl connect up --token-file \"" + setupToken + "\"" + operations
		return long, example
	}
	long := base + "\n\nStart with serve in an interactive user terminal for guided setup.\nConnect asks before installing a background service, uses datumctl login and\nyour current project, and enrolls this device before sharing.\nUse up for explicit enrollment or reconnecting. Scripts and privileged\nservices require explicit setup and authorization."
	example := "  # Share an existing application (guides first-time setup)\n  datumctl connect serve localhost:8080\n\n  # Enroll without sharing, or reconnect an existing device\n  datumctl connect up" + operations
	return long, example
}
