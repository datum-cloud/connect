// Package signals provides signal forwarding from parent to child process.
package signals

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Forward sets up signal forwarding from parent to child process.
// On SIGINT/SIGTERM (unix) or Ctrl+C/Ctrl+Break (windows), forwards
// the signal to child and waits up to gracePeriod for clean shutdown.
//
// childExited must be closed by the caller after cmd.Wait() returns — this
// avoids a double-Wait race where both Forward and the caller try to reap the
// same process, which can cause the caller's ProcessState to be nil.
//
// Platform behavior:
//   - Unix: receives SIGINT/SIGTERM, forwards to child, waits gracePeriod,
//     then sends SIGKILL if child hasn't exited
//   - Windows: Go's signal.Notify with SIGINT handles Ctrl+C automatically.
//     Force-kill uses os.Process.Kill().
//
// Returns nil on success. The child's exit code is available via
// cmd.ProcessState.ExitCode() after Wait().
func Forward(child *os.Process, childExited <-chan struct{}, gracePeriod time.Duration) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(ch)

	select {
	case sig := <-ch:
		// Received signal — forward to child
		_ = child.Signal(sig)

		// Wait for child to exit within grace period
		select {
		case <-childExited:
			return nil
		case <-time.After(gracePeriod):
			// Grace period expired — force kill
			_ = child.Signal(syscall.SIGKILL)
			<-childExited
			return nil
		}
	case <-childExited:
		// Child exited before receiving signal — nothing to forward
		return nil
	}
}
