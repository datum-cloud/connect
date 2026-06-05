package logs

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logs",
		Short: "View tunnel logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "not implemented (Phase 5)")
			return nil
		},
	}
}
