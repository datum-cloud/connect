package listen

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/binary"
	"go.datum.net/datumctl-plugins/connect/internal/daemon"
	"go.datum.net/datumctl-plugins/connect/internal/env"
	rexec "go.datum.net/datumctl-plugins/connect/internal/exec"
	"go.datum.net/datumctl-plugins/connect/internal/supervise"
	"go.datum.net/datumctl/plugin"
)

const (
	// startupTimeout is the maximum time to wait for the first typed message
	// (ready or error) from the Rust binary.
	startupTimeout = 10 * time.Minute
	// gracePeriod is the time to wait for clean shutdown after sending SIGINT.
	gracePeriod = 30 * time.Second
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "listen [flags]",
		Short:        "Start a tunnel and block",
		SilenceUsage: true,
		RunE:         runListen,
	}
	cmd.Flags().String("label", "", "Display name for the tunnel")
	cmd.Flags().String("origin", "", "Local address to expose (host:port, required)")
	cmd.Flags().String("id", "", "Existing tunnel resource name to resume (mutually inclusive with optional --origin)")
	cmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	cmd.Flags().Bool("detach", false, "Run in background (daemon mode)")
	cmd.Flags().String("name", "", "Tunnel name (required with --detach)")
	cmd.Flags().String("log-file", "", "Path for Rust debug log output")
	cmd.Flags().StringP("output", "o", "table", "Output format: table, json, yaml")
	return cmd
}

func runListen(cmd *cobra.Command, args []string) error {
	label, _ := cmd.Flags().GetString("label")
	origin, _ := cmd.Flags().GetString("origin")
	id, _ := cmd.Flags().GetString("id")
	yes, _ := cmd.Flags().GetBool("yes")
	detach, _ := cmd.Flags().GetBool("detach")
	name, _ := cmd.Flags().GetString("name")
	logFile, _ := cmd.Flags().GetString("log-file")

	if origin == "" && id == "" {
		// Neither flag given — semantic rejection (EXIT-02).
		// The Rust binary requires at least one of --origin or --id;
		// when neither is set and stdin is non-interactive the picker
		// also can't run, so reject here for a faster, clearer error.
		fmt.Fprintln(os.Stderr, "Error: --origin or --id is required")
		os.Exit(64) // POSIX: semantic rejection (EXIT-02)
	}

	// Detach mode: spawn background daemon and exit
	if detach {
		if id != "" {
			fmt.Fprintln(os.Stderr, "Error: --id is not supported with --detach. Use 'tunnel run --name N' for detached named tunnels")
			os.Exit(64)
		}
		if name == "" {
			fmt.Fprintln(os.Stderr, "Error: --name is required with --detach")
			os.Exit(64)
		}
		exe := daemon.SelfExe()
		childArgs := daemon.ForegroundArgs(name, logFile, origin, label, yes)
		_, err := daemon.Daemonize(exe, append([]string{exe}, childArgs...))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: daemonize: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Tunnel '%s' setting up in background; tunnel status will show progress\n", name)
		return nil
	}

	// Discover binary
	binaryPath, err := binary.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get plugin context
	pluginCtx := plugin.Context()

	// Build environment (no DATUM_ACCESS_TOKEN — binary obtains token via credentials helper)
	childEnv := env.Build(pluginCtx)

	// Pass tunnel name to the Rust binary so it can construct the
	// per-tunnel key path. Only set when the name is known upfront
	// (detach mode). For --origin-only and picker paths, the name
	// comes from the server after tunnel creation (handled in Rust).
	if name != "" {
		childEnv = append(childEnv, "DATUM_CONNECT_TUNNEL_NAME="+name)
	}

	rustArgs := supervise.BuildListenArgs(pluginCtx.Project, origin, id, label, yes)

	// Determine mode
	isJSON := false
	if outputFlag, _ := cmd.Flags().GetString("output"); outputFlag == "json" {
		isJSON = true
	}

	// childErr holds a typed error emitted by the child before tunnel_ready.
	// It is surfaced as the command error when the child exits during setup,
	// instead of masking the real cause behind a generic "child exited" message.
	var childErr string
	var gotReady bool

	result, err := supervise.Run(context.Background(), supervise.Config{
		BinaryPath:     binaryPath,
		Args:           rustArgs,
		Env:            childEnv,
		Stderr:         os.Stderr,
		StartupTimeout: startupTimeout,
		GracePeriod:    gracePeriod,
	}, func(msg rexec.TypedMessage) bool {
		switch msg.Type {
		case "tunnel_ready":
			gotReady = true
			if isJSON {
				// JSON mode: print ready JSON and stop reading further
				// messages — pipe-buffered stdout won't flush without the
				// newline Fprintln adds back (the scanner stripped it).
				fmt.Fprintln(cmd.OutOrStdout(), string(msg.Raw))
				return true
			}
			// Interactive mode: print hostname
			var ready supervise.TunnelReady
			data, _ := json.Marshal(msg.Fields)
			_ = json.Unmarshal(data, &ready)
			if len(ready.Hostnames) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Tunnel ready: https://%s\n", ready.Hostnames[0])
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Press Ctrl+C to stop...")
		case "error":
			if msg.Message != "" {
				if gotReady {
					// Mid-session error after ready — surface to stderr
					// and keep the tunnel running.
					fmt.Fprintf(os.Stderr, "error: %s\n", msg.Message)
				} else {
					// Setup error before ready — capture it so it becomes
					// the command error below, surfacing the real cause.
					childErr = msg.Message
				}
			}
		case "heartbeat", "status":
			// Internal messages — no output
		case "tunnel_progress", "tunnel_verifying", "tunnel_verified":
			// Per-step setup-time status events from the Rust binary's
			// await_tunnel_progress / verify_endpoints (Phase 12-03).
			// Currently no-op at the supervisor layer — the human-friendly
			// ready line is what we surface. Phase 13 may forward these
			// to a future progress UI.
		case "tunnel_terminal_failure", "tunnel_login_lost", "tunnel_deleted_upstream":
			// Mid-session degradation signals from the Rust binary's runtime
			// poll loop (Phase 12-04). Forward the message field to stderr so
			// the user sees it; the child will exit on its own shortly.
			if msg.Message != "" {
				fmt.Fprintln(os.Stderr, msg.Message)
			}
		case "tunnel_disabled":
			// Emitted by the Rust binary's cleanup block (Phase 12-04).
			// No-op at supervisor layer; the child is about to exit.
		case "tunnel_created", "tunnel_updated":
			// Lifecycle events from create/update paths. No supervisor
			// action needed in plugin/listen mode; tunnel_ready still
			// drives gotReady.
		case "tunnel_deleted":
			// Emitted only by the `delete` subcommand. Not seen on the
			// listen path.
		default:
			// Unknown type — skip
		}
		return false
	})

	if err != nil {
		if errors.Is(err, supervise.ErrExitedBeforeReady) && childErr != "" {
			return fmt.Errorf("%s", childErr)
		}
		return err
	}

	if !result.GotReady {
		return fmt.Errorf("no ready message received from child")
	}

	return nil
}
