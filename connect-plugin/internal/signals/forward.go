// Package signals provides signal forwarding from parent to child process.
package signals

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Forward forwards SIGINT/SIGTERM (unix) or Ctrl+C/Ctrl+Break (windows)
// from the parent to child and waits up to gracePeriod for a clean
// shutdown before force-killing it.
//
// childExited must be closed by the caller once its own cmd.Wait() has
// returned. Forward never calls Wait itself: a process may only be waited
// on once, and a second concurrent Wait races the first for the exit
// status, leaving the loser with no ProcessState and a bogus exit code 0.
//
// Platform behavior:
//   - Unix: receives SIGINT/SIGTERM, forwards to child, waits gracePeriod,
//     then sends SIGKILL if child hasn't exited
//   - Windows: Go's signal.Notify with SIGINT handles Ctrl+C automatically.
//     Ctrl+Break maps to SIGINT via the Go runtime. Force-kill uses
//     os.Process.Kill() (Windows equivalent of SIGKILL).
//
// Returns once the child has exited.
func Forward(child *os.Process, childExited <-chan struct{}, gracePeriod time.Duration) {
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
		case <-time.After(gracePeriod):
			// Grace period expired — force kill
			_ = child.Signal(syscall.SIGKILL)
			<-childExited
		}
	case <-childExited:
		// Child exited before receiving signal — nothing to forward
	}
}
