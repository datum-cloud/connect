// Package supervise provides shared process-supervision logic for spawning
// the Rust tunnel binary, streaming its typed JSON stdout messages, and
// handling startup timeout / signal-driven shutdown.
//
// Both `tunnel listen` and `tunnel interactive` build on this: they differ
// only in how they render the message stream (plain text/JSON for listen,
// a live dashboard for interactive), not in how the child process itself is
// spawned, timed out, or shut down.
package supervise

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	rexec "go.datum.net/datumctl-plugins/connect/internal/exec"
)

// TunnelReady is the "tunnel_ready" message shape emitted by the Rust binary.
type TunnelReady struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Endpoint  string   `json:"endpoint"`
	Hostnames []string `json:"hostnames"`
	Status    string   `json:"status"`
}

// ErrExitedBeforeReady is returned by Run when the child's stdout closes —
// meaning the child exited — before any tunnel_ready message was seen.
// Callers that captured a more specific pre-ready "error" message via
// onMessage should prefer surfacing that instead of this generic error.
var ErrExitedBeforeReady = errors.New("child exited before sending ready message")

// Config holds the parameters for spawning and supervising the Rust tunnel binary.
type Config struct {
	BinaryPath string
	Args       []string
	Env        []string
	// Stderr is where the child's stderr is forwarded; defaults to os.Stderr.
	Stderr io.Writer
	// StartupTimeout bounds how long to wait for the first tunnel_ready
	// message before killing the child and returning a timeout error.
	StartupTimeout time.Duration
	// GracePeriod bounds how long to wait for the child to exit cleanly
	// after a shutdown signal is forwarded, before escalating to SIGKILL.
	GracePeriod time.Duration
}

// Result summarizes how a supervised Run ended.
type Result struct {
	GotReady bool
	Ready    TunnelReady
}

// BuildListenArgs constructs the Rust binary's CLI arguments for its
// `listen` subcommand. Shared by `tunnel listen` and `tunnel interactive`,
// which both drive the same Rust entry point.
func BuildListenArgs(project, endpoint, id, label string, yes bool) []string {
	args := []string{"--json", "--project", project, "listen"}
	if endpoint != "" {
		args = append(args, "--endpoint", endpoint)
	}
	if id != "" {
		args = append(args, "--id", id)
	}
	if label != "" {
		args = append(args, "--label", label)
	}
	if yes {
		args = append(args, "--yes")
	}
	return args
}

// Run spawns cfg.BinaryPath with cfg.Args/cfg.Env and streams its stdout as
// typed JSON messages to onMessage, called once per message — both before
// and after readiness — in arrival order.
//
// onMessage returns stop=true to stop rendering further messages (the child
// keeps running, and Run still watches for shutdown signals) — used by
// listen's --output json mode, which only wants the single ready line.
//
// Run blocks until one of:
//   - a SIGINT/SIGTERM arrives: forwarded to the child, then Run waits up to
//     cfg.GracePeriod for it to exit before escalating to SIGKILL. Returns
//     a nil error.
//   - the child's stdout closes before any tunnel_ready was seen: Run
//     returns ErrExitedBeforeReady. Callers that captured a more specific
//     pre-ready error via onMessage should prefer surfacing that.
//   - cfg.StartupTimeout elapses without a tunnel_ready: the child is
//     killed and Run returns a timeout error.
//   - a malformed line is read from the child's stdout (a protocol
//     violation that should never occur): the child is reaped and Run
//     returns that error.
func Run(ctx context.Context, cfg Config, onMessage func(rexec.TypedMessage) (stop bool)) (Result, error) {
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	cmd := exec.CommandContext(ctx, cfg.BinaryPath, cfg.Args...)
	cmd.Env = cfg.Env
	cmd.Stderr = stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("failed to start %s: %w", cfg.BinaryPath, err)
	}

	// waitCh delivers cmd.Wait()'s result exactly once — every branch below
	// reads from it to reap the child instead of calling cmd.Wait() itself,
	// since calling Wait twice is invalid.
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	msgCh := make(chan rexec.TypedMessage)
	scanErrCh := make(chan error, 1) // non-nil only on a malformed line
	go func() {
		defer close(msgCh)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			msg, ok := rexec.ParseTypedMessage(line)
			if !ok {
				scanErrCh <- fmt.Errorf("malformed message from child: %s", line)
				return
			}
			msgCh <- msg
		}
		scanErrCh <- nil
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var result Result
	var timeout <-chan time.Time
	if cfg.StartupTimeout > 0 {
		timer := time.NewTimer(cfg.StartupTimeout)
		defer timer.Stop()
		timeout = timer.C
	}
	stopped := false

	for {
		select {
		case msg, ok := <-msgCh:
			if !ok {
				// Child's stdout closed — reap it and report why.
				scanErr := <-scanErrCh
				<-waitCh
				if scanErr != nil {
					return result, scanErr
				}
				if !result.GotReady {
					return result, ErrExitedBeforeReady
				}
				return result, nil
			}
			if msg.Type == "tunnel_ready" && !result.GotReady {
				result.GotReady = true
				result.Ready = parseReady(msg)
				timeout = nil // startup timeout no longer applies
			}
			if stopped {
				continue
			}
			if onMessage(msg) {
				stopped = true
			}
		case <-timeout:
			_ = cmd.Process.Signal(syscall.SIGKILL)
			<-waitCh
			return result, fmt.Errorf("timed out waiting for tunnel ready after %v", cfg.StartupTimeout)
		case sig := <-sigCh:
			_ = cmd.Process.Signal(sig)
			select {
			case <-waitCh:
			case <-time.After(cfg.GracePeriod):
				_ = cmd.Process.Signal(syscall.SIGKILL)
				<-waitCh
			}
			return result, nil
		}
	}
}

func parseReady(msg rexec.TypedMessage) TunnelReady {
	var ready TunnelReady
	data, _ := json.Marshal(msg.Fields)
	_ = json.Unmarshal(data, &ready)
	return ready
}
