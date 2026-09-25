package vpc

import (
	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/vpc/join"
)

// NewCmd returns the vpc root command with all subcommands.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vpc",
		Short: "Manage VPC attachments",
		Long:  "Join a local interface to a Datum Cloud galactic VPC via Datum Connect",
	}

	cmd.AddCommand(join.NewCmd())

	return cmd
}
