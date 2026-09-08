// Package interactive implements `tunnel interactive`: a foreground tunnel
// session with a live dashboard of the tunnel's status and traffic.
package interactive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/binary"
	"go.datum.net/datumctl-plugins/connect/internal/dummyorigin"
	"go.datum.net/datumctl-plugins/connect/internal/env"
	rexec "go.datum.net/datumctl-plugins/connect/internal/exec"
	"go.datum.net/datumctl-plugins/connect/internal/supervise"
	"go.datum.net/datumctl-plugins/connect/internal/tui"
	"go.datum.net/datumctl/plugin"
)

const (
	startupTimeout         = 10 * time.Minute
	gracePeriod            = 30 * time.Second
	defaultDummyOriginAddr = "localhost:8888"
	dummyOriginShutdown    = 5 * time.Second
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "interactive [flags]",
		Short:         "Start a tunnel with a live interactive dashboard",
		SilenceUsage:  true,
		SilenceErrors: true, // main.go already prints "Error: %v" itself; without this cobra prints it a second time
		RunE:          runInteractive,
	}
	cmd.Flags().String("origin", "", "Local address to expose (host:port)")
	cmd.Flags().Bool("dummy-origin", false, "Serve a built-in dummy HTTP origin on --origin instead of a real local service (defaults --origin to "+defaultDummyOriginAddr+")")
	cmd.Flags().String("label", "", "Display name for the tunnel")
	cmd.Flags().String("id", "", "Existing tunnel resource name to resume; combine with --origin to re-point its endpoint")
	cmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	cmd.Flags().String("log-file", "", "Path for Rust debug log output")
	return cmd
}

func runInteractive(cmd *cobra.Command, args []string) error {
	origin, _ := cmd.Flags().GetString("origin")
	dummy, _ := cmd.Flags().GetBool("dummy-origin")
	label, _ := cmd.Flags().GetString("label")
	id, _ := cmd.Flags().GetString("id")
	yes, _ := cmd.Flags().GetBool("yes")

	// --dummy-origin + --id is allowed: the Rust binary already supports
	// re-pointing an existing tunnel's endpoint via --id + --endpoint
	// together (the same mechanism --label uses to rewire a resumed
	// tunnel), so resuming a known-working tunnel and re-pointing it at a
	// fresh dummy origin is a legitimate combination, not a conflict.
	if dummy && origin == "" {
		origin = defaultDummyOriginAddr
	}
	if origin == "" && id == "" {
		fmt.Fprintln(os.Stderr, "Error: --origin or --id is required")
		os.Exit(64)
	}

	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		// The dashboard needs a real TTY: it puts the terminal in raw mode to
		// read keystrokes and redraws in place via the alt-screen buffer.
		// Piped/redirected stdin or stdout (scripts, CI, `| less`, tests)
		// would either hang reading input or scramble a downstream pipe with
		// raw ANSI escapes — reject early with a clear message instead.
		fmt.Fprintln(os.Stderr, "Error: tunnel interactive requires a terminal (TTY) on stdin and stdout; use 'tunnel listen' for non-interactive/scripted use")
		os.Exit(1)
	}

	binaryPath, err := binary.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pluginCtx := plugin.Context()
	childEnv := env.Build(pluginCtx)
	rustArgs := supervise.BuildListenArgs(pluginCtx.Project, origin, id, label, yes)

	// program is assigned below, after it's constructed — but the dummy
	// origin's onRequest callback needs to close over it now, since the
	// server must bind (to learn its real address, e.g. when --origin
	// asks for host:0) before the model can be built with that address.
	// The callback only ever fires on an actual HTTP request, which can't
	// happen before program is assigned a few lines down.
	var program *tea.Program

	dummyOriginAddr := ""
	if dummy {
		srv, err := dummyorigin.Start(origin, func(method, path string) {
			if program != nil {
				program.Send(tui.RequestMsg{Method: method, Path: path, At: time.Now()})
			}
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		dummyOriginAddr = srv.Addr()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), dummyOriginShutdown)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
	}

	onQuit := func() {
		// Bubbletea puts the terminal in raw mode, so a 'q'/ctrl+c keypress
		// never arrives at this process as a real SIGINT — self-signal to
		// trigger the same forward-and-grace-shutdown path supervise.Run
		// already runs for an external Ctrl+C.
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	}
	model := tui.New(label, origin, dummyOriginAddr, onQuit)
	program = tea.NewProgram(model, tea.WithoutSignalHandler())

	var childErr string
	var gotReady bool
	var result supervise.Result
	var runErr error
	// stderrTail captures the Rust child's stderr instead of forwarding it
	// straight to the terminal (which would corrupt the alt-screen) — kept
	// so a pre-ready crash the child didn't report as a typed "error"
	// message (a panic, a Rust-side log line, anything not going through
	// the JSON protocol) is still visible in the failure we return, rather
	// than a bare "child exited before sending ready message".
	stderrTail := newCappedBuffer(16 * 1024)
	done := make(chan struct{})

	go func() {
		defer close(done)
		result, runErr = supervise.Run(context.Background(), supervise.Config{
			BinaryPath:     binaryPath,
			Args:           rustArgs,
			Env:            childEnv,
			Stderr:         stderrTail,
			StartupTimeout: startupTimeout,
			GracePeriod:    gracePeriod,
		}, func(msg rexec.TypedMessage) bool {
			if msg.Type == "tunnel_ready" {
				gotReady = true
			} else if msg.Type == "error" && msg.Message != "" && !gotReady {
				childErr = msg.Message
			}
			program.Send(tui.MessageMsg{Msg: msg})
			return false
		})
		program.Quit()
	}()

	_, progErr := program.Run()
	<-done

	if runErr != nil {
		if errors.Is(runErr, supervise.ErrExitedBeforeReady) {
			if childErr != "" {
				return fmt.Errorf("%s", childErr)
			}
			if tail := stderrTail.String(); tail != "" {
				return fmt.Errorf("%w:\n%s", runErr, tail)
			}
		}
		return runErr
	}
	if !result.GotReady {
		return fmt.Errorf("no ready message received from child")
	}
	if progErr != nil && !errors.Is(progErr, tea.ErrInterrupted) {
		return fmt.Errorf("tui: %w", progErr)
	}
	return nil
}

// cappedBuffer is an io.Writer that keeps only the last maxBytes written to
// it, safe for concurrent Write (from the Rust child's stderr pump) and
// String (read once after the child has exited).
type cappedBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	maxSize int
}

func newCappedBuffer(maxSize int) *cappedBuffer {
	return &cappedBuffer{maxSize: maxSize}
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.buf.Write(p)
	if over := c.buf.Len() - c.maxSize; over > 0 {
		c.buf.Next(over) // drop oldest bytes
	}
	return n, err
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.TrimSpace(c.buf.String())
}

// isTerminal reports whether f is a character device (a real terminal),
// as opposed to a pipe, redirected file, or /dev/null. Dependency-free
// alternative to golang.org/x/term.IsTerminal — good enough for a yes/no
// gate, not full terminal capability detection.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
