// Package signals provides signal forwarding from parent to child process.
package signals

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Forward relays SIGINT or SIGTERM to child and gives it gracePeriod to exit.
// Signal delivery follows os.Process.Signal platform support; if the child
// remains alive, Forward terminates it with os.Process.Kill.
//
// childExited must be closed by the caller after cmd.Wait() returns so this
// function never races the caller to reap the same process.
//
// Returns nil on success. The child's exit code is available via
// cmd.ProcessState.ExitCode() after Wait().
func Forward(child *os.Process, childExited <-chan struct{}, gracePeriod time.Duration) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(ch)
	return forward(child, childExited, gracePeriod, ch)
}

type childProcess interface {
	Signal(os.Signal) error
	Kill() error
}

func forward(child childProcess, childExited <-chan struct{}, gracePeriod time.Duration, signals <-chan os.Signal) error {
	select {
	case sig := <-signals:
		// Some platforms cannot relay every signal; the grace timeout still
		// provides a portable forced-termination fallback.
		_ = child.Signal(sig)

		timer := time.NewTimer(gracePeriod)
		defer timer.Stop()
		select {
		case <-childExited:
			return nil
		case <-timer.C:
			if err := child.Kill(); err != nil {
				if errors.Is(err, os.ErrProcessDone) {
					<-childExited
					return nil
				}
				return fmt.Errorf("kill child after grace period: %w", err)
			}
			<-childExited
			return nil
		}
	case <-childExited:
		return nil
	}
}
