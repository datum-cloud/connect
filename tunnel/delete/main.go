package delete

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Delete a tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "not implemented (Phase 4)")
			return nil
		},
	}
}
