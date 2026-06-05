package listen

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "listen",
		Short: "Start a tunnel and block",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "not implemented (Phase 4)")
			return nil
		},
	}
}
