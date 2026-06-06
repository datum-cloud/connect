package stop

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/pidfile"
	"go.datum.net/datumctl-plugins/connect/internal/state"
)

const (
	gracePeriod = 30 * time.Second
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop --name N",
		Short: "Stop a tunnel",
		RunE:  runStop,
	}
	cmd.Flags().String("name", "", "Tunnel name (required)")
	return cmd
}

func runStop(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		os.Exit(64)
	}

	pidPath := state.PidFilePath(name)
	pf, err := pidfile.Read(pidPath)
	if err != nil {
		return fmt.Errorf("tunnel '%s' not running: %w", name, err)
	}

	// Kill Rust child first (per CONTEXT.md stop flow)
	rustProc, err := os.FindProcess(pf.RustPID)
	if err == nil {
		// Send SIGTERM to Rust
		_ = rustProc.Signal(syscall.SIGTERM)
	}

	// Wait up to grace period for Rust to exit
	done := make(chan struct{})
	go func() {
		for i := 0; i < int(gracePeriod/time.Second); i++ {
			if !pidfile.PIDAlive(pf.RustPID) {
				close(done)
				return
			}
			time.Sleep(time.Second)
		}
		// Timeout — force kill Rust
		if rustProc != nil {
			_ = rustProc.Signal(syscall.SIGKILL)
		}
		close(done)
	}()
	<-done

	// Clean up PID file
	_ = pidfile.Remove(pidPath)

	fmt.Fprintf(cmd.OutOrStdout(), "Tunnel '%s' stopped\n", name)
	return nil
}
