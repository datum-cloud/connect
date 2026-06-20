package main

import (
	"fmt"
	"os"

	"go.datum.net/datumctl-plugins/connect/internal/env"
	"go.datum.net/datumctl-plugins/connect/tunnel"
	"go.datum.net/datumctl/plugin"
)

// Overridden at release time via -ldflags "-X main.version=vX.Y.Z".
// See .goreleaser.yaml.
var version = "v0.1.0"

func main() {
	// Serve manifest before cobra parses anything
	m := plugin.Manifest{
		Name:        "connect",
		Version:     version,
		Description: "Manage Datum Connect tunnels",
		APIVersion:  1,
	}
	plugin.ServeManifest(m)

	// Phase 11.5 D-09/D-10/D-11: refuse to run any tunnel subcommand
	// when DATUM_CONNECT_DIR is unset. ServeManifest above already
	// self-exits for the --plugin-manifest probe, so by this point
	// we are committed to running a real subcommand.
	if err := env.RequireConnectDir(); err != nil {
		env.FailConnectDirUnset(os.Stderr, err)
		os.Exit(64)
	}

	// Create root command with pre-wired flags
	cmd := plugin.NewRootCmd("connect", "Manage Datum Connect tunnels")
	cmd.AddCommand(tunnel.NewCmd())

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
