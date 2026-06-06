package status

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/pidfile"
	"go.datum.net/datumctl-plugins/connect/internal/state"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status --name N",
		Short: "Show tunnel status",
		RunE:  runStatus,
	}
	cmd.Flags().String("name", "", "Tunnel name (required)")
	return cmd
}

func runStatus(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		os.Exit(64)
	}

	pidPath := state.PidFilePath(name)
	pf, err := pidfile.Read(pidPath)
	if err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Tunnel '%s': Stopped\n", name)
		return nil
	}

	goAlive := pidfile.PIDAlive(pf.GoPID)
	rustAlive := pidfile.PIDAlive(pf.RustPID)

	status := computeStatus(goAlive, rustAlive)
	uptime := formatDuration(time.Since(pf.StartTime))

	fmt.Fprintf(cmd.OutOrStdout(), "Tunnel:      %s\n", name)
	fmt.Fprintf(cmd.OutOrStdout(), "Status:      %s\n", status)
	fmt.Fprintf(cmd.OutOrStdout(), "Go PID:      %d (alive: %v)\n", pf.GoPID, goAlive)
	fmt.Fprintf(cmd.OutOrStdout(), "Rust PID:    %d (alive: %v)\n", pf.RustPID, rustAlive)
	fmt.Fprintf(cmd.OutOrStdout(), "Started:     %s\n", pf.StartTime.Format(time.RFC3339))
	fmt.Fprintf(cmd.OutOrStdout(), "Uptime:      %s\n", uptime)
	fmt.Fprintf(cmd.OutOrStdout(), "Binary:      %s\n", pf.BinaryPath)

	return nil
}

func computeStatus(goAlive, rustAlive bool) string {
	switch {
	case !goAlive && !rustAlive:
		return "Stopped"
	case goAlive && rustAlive:
		return "Running"
	case goAlive && !rustAlive:
		return "Degraded"
	case !goAlive && rustAlive:
		return "Zombie"
	default:
		return "Unknown"
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
