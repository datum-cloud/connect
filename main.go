package main

import (
	"fmt"
	"os"

	"go.datum.net/datumctl-plugins/connect/tunnel"
	"go.datum.net/datumctl/plugin"
)

func main() {
	// Serve manifest before cobra parses anything
	m := plugin.Manifest{
		Name:        "connect",
		Version:     "v0.1.0",
		Description: "Manage Datum Connect tunnels",
		APIVersion:  1,
	}
	plugin.ServeManifest(m)

	// Create root command with pre-wired flags
	cmd := plugin.NewRootCmd("connect", "Manage Datum Connect tunnels")
	cmd.AddCommand(tunnel.NewCmd())

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
