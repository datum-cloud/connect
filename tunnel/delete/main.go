package delete

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/binary"
	"go.datum.net/datumctl-plugins/connect/internal/env"
	"go.datum.net/datumctl-plugins/connect/internal/exec"
	"go.datum.net/datumctl-plugins/connect/internal/output"
	"go.datum.net/datumctl/plugin"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [flags]",
		Short: "Delete a tunnel",
		RunE:  runDelete,
	}
	cmd.Flags().String("id", "", "Tunnel ID to delete (required)")
	return cmd
}

func runDelete(cmd *cobra.Command, args []string) error {
	id, _ := cmd.Flags().GetString("id")

	if id == "" {
		fmt.Fprintln(os.Stderr, "Error: --id is required")
		os.Exit(64) // POSIX: semantic rejection (EXIT-02)
	}

	// Discover binary
	binaryPath, err := binary.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get token
	pluginCtx := plugin.Context()
	token, err := plugin.Token()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Build env
	childEnv := env.Build(pluginCtx, token)

	// Run: --json delete --id X
	result, err := exec.Run(context.Background(), binaryPath, []string{"--json", "delete", "--id", id}, childEnv, exec.OutputModeJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if result.ExitCode != 0 {
		if len(result.Stderr) > 0 {
			fmt.Fprintln(os.Stderr, strings.TrimSpace(string(result.Stderr)))
		}
		os.Exit(result.ExitCode)
	}

	// Output: JSON mode passes through, YAML converts, table renders
	outputFlag, _ := cmd.Flags().GetString("output")
	switch outputFlag {
	case "json":
		fmt.Fprint(cmd.OutOrStdout(), string(result.Stdout))
	case "yaml":
		yaml, err := output.ConvertJSONToYAML(result.Stdout)
		if err != nil {
			fmt.Fprint(cmd.OutOrStdout(), string(result.Stdout))
		} else {
			fmt.Fprint(cmd.OutOrStdout(), string(yaml))
		}
	default:
		// Table mode for single object
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		if err := output.RenderTable(result.Stdout, w); err != nil {
			fmt.Fprint(cmd.OutOrStdout(), string(result.Stdout))
		}
	}

	return nil
}
