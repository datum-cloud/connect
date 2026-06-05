package status

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show tunnel status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "not implemented (Phase 5)")
			return nil
		},
	}
}
