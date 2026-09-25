package join

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/binary"
	"go.datum.net/datumctl-plugins/connect/internal/env"
	rexec "go.datum.net/datumctl-plugins/connect/internal/exec"
	"go.datum.net/datumctl/plugin"
)

const (
	// startupTimeout is the maximum time to wait for the vpc_ready message
	// from the Rust binary. Shorter than tunnel's — there's no DNS/HTTP
	// verification step here, just local interface setup.
	startupTimeout = 2 * time.Minute
	// gracePeriod is the time to wait for clean shutdown after sending SIGINT.
	gracePeriod = 30 * time.Second
)

// VpcReady represents the vpc_ready message from the Rust binary.
type VpcReady struct {
	Vpc        string   `json:"vpc"`
	EndpointID string   `json:"endpoint_id"`
	BoundAddrs []string `json:"bound_addrs"`
	Address    string   `json:"address"`
	TunName    string   `json:"tun_name"`
	Mode       string   `json:"mode"`
}

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "join [flags]",
		Short:        "Create a local interface and join a galactic VPC",
		Long: "Create a local interface and join a galactic VPC.\n\n" +
			"Scaffolding ahead of the real galactic-side control plane: this resolves\n" +
			"the attachment's address/prefixes/mode/router-identity from flags rather\n" +
			"than a VPCAttachment resource (see design/vpc-attachment.md).",
		SilenceUsage: true,
		RunE:         runJoin,
	}
	cmd.Flags().String("vpc", "", "VPC name/id (required; label only for now, not yet resolved via a resource)")
	cmd.Flags().String("router-id", "", "iroh EndpointId of the galactic-side router allowed to dial in. Omit to accept any dialer (trust-on-first-connect) — lab/dev use only")
	cmd.Flags().String("tun-name", "datum-vpc0", "Name of the local TUN interface to create")
	cmd.Flags().Int("mtu", 1280, "MTU for the local TUN interface")
	cmd.Flags().String("mode", "vpc-only", "vpc-only (default) or default-route")
	cmd.Flags().String("router-ip", "", "Concrete IP of the galactic router; only used to pin a host route in default-route mode (see datum-connect vpc join --help)")
	cmd.Flags().StringP("output", "o", "table", "Output format: table, json, yaml")
	_ = cmd.MarkFlagRequired("vpc")
	return cmd
}

func runJoin(cmd *cobra.Command, args []string) error {
	vpcName, _ := cmd.Flags().GetString("vpc")
	routerID, _ := cmd.Flags().GetString("router-id")
	tunName, _ := cmd.Flags().GetString("tun-name")
	mtu, _ := cmd.Flags().GetInt("mtu")
	mode, _ := cmd.Flags().GetString("mode")
	routerIP, _ := cmd.Flags().GetString("router-ip")

	binaryPath, err := binary.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pluginCtx := plugin.Context()
	childEnv := env.Build(pluginCtx)

	rustArgs := []string{
		"--json", "vpc", "join",
		"--vpc", vpcName,
		"--tun-name", tunName,
		"--mtu", strconv.Itoa(mtu),
		"--mode", mode,
	}
	if routerID != "" {
		rustArgs = append(rustArgs, "--router-id", routerID)
	}
	if routerIP != "" {
		rustArgs = append(rustArgs, "--router-ip", routerIP)
	}

	rustCmd := exec.CommandContext(context.Background(), binaryPath, rustArgs...)
	rustCmd.Env = childEnv

	// Capture stdout for JSON parsing; stderr forwarded transparently.
	stdoutReader, err := rustCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	rustCmd.Stderr = os.Stderr

	if err := rustCmd.Start(); err != nil {
		return fmt.Errorf("failed to start datum-connect: %w", err)
	}

	isJSON := false
	if outputFlag, _ := cmd.Flags().GetString("output"); outputFlag == "json" {
		isJSON = true
	}

	scanner := bufio.NewScanner(stdoutReader)
	var ready VpcReady
	var gotReady bool
	// childErr holds a typed error emitted by the child before vpc_ready.
	var childErr string

	readDone := make(chan struct{})
	readyCh := make(chan struct{})
	go func() {
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			msg, ok := rexec.ParseTypedMessage(line)
			if !ok {
				rustCmd.Wait()
				fmt.Fprintf(os.Stderr, "malformed message from child: %s\n", line)
				return
			}

			switch msg.Type {
			case "vpc_listening":
				if isJSON {
					fmt.Fprintln(cmd.OutOrStdout(), string(line))
				} else {
					if eid, ok := msg.Fields["endpoint_id"]; ok {
						fmt.Fprintf(cmd.OutOrStdout(), "Endpoint ID: %v\n", eid)
					}
					fmt.Fprintln(cmd.OutOrStdout(), "Waiting for router to assign address...")
				}
			case "vpc_ready":
				readyData, _ := json.Marshal(msg.Fields)
				_ = json.Unmarshal(readyData, &ready)
				gotReady = true

				if isJSON {
					fmt.Fprintln(cmd.OutOrStdout(), string(line))
					close(readyCh)
					return
				}
				fmt.Fprintf(cmd.OutOrStdout(), "VPC attachment ready: %s at %s via %s (mode %s)\n",
					ready.Vpc, ready.Address, ready.TunName, ready.Mode)
				fmt.Fprintf(cmd.OutOrStdout(), "Listening on: %s\n", strings.Join(ready.BoundAddrs, ", "))
				fmt.Fprintln(cmd.OutOrStdout(), "Press Ctrl+C to stop...")
				close(readyCh)
			case "error":
				if msg.Message != "" {
					if gotReady {
						fmt.Fprintf(os.Stderr, "error: %s\n", msg.Message)
					} else {
						childErr = msg.Message
					}
				}
			default:
				// Unknown/progress event types — no-op at the supervisor
				// layer, same policy as tunnel's listen command.
			}
		}
		close(readDone)
	}()

	select {
	case <-readyCh:
	case <-time.After(startupTimeout):
		_ = rustCmd.Process.Signal(syscall.SIGKILL)
		_ = rustCmd.Wait()
		return fmt.Errorf("timed out waiting for vpc ready after %v", startupTimeout)
	case <-readDone:
		if childErr != "" {
			return fmt.Errorf("%s", childErr)
		}
		return fmt.Errorf("child exited before sending ready message")
	}

	if !gotReady {
		return fmt.Errorf("no ready message received from child")
	}

	// Block until signal (Ctrl+C / SIGINT / SIGTERM), then forward it and
	// wait for clean shutdown with a grace period.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	_ = rustCmd.Process.Signal(sig)

	done := make(chan error, 1)
	go func() {
		done <- rustCmd.Wait()
	}()

	select {
	case <-done:
		return nil
	case <-time.After(gracePeriod):
		_ = rustCmd.Process.Signal(syscall.SIGKILL)
		<-done
		return nil
	}
}
