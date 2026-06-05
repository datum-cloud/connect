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
// Returns the child's exit code.
func Forward(child *os.Process, gracePeriod time.Duration) error {
	// TODO: Phase 2 — implement signal forwarding
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	_ = gracePeriod
	return nil
}
