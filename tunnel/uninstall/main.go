package uninstall

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall a tunnel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "not implemented (Phase 6)")
			return nil
		},
	}
}
