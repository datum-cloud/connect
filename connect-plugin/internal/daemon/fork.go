// Package daemon provides functions to fork processes into daemons.
package daemon

import (
	"fmt"
	"os"
)

// Daemonize spawns a detached copy of the current Go binary as a background
// daemon. Uses os.StartProcess to create a new process with no terminal
// association. This is the cross-platform approach — fork() is not available
// on Windows.
//
// The child process runs tunnel run --name N which calls RunSupervisor.
//
// Returns the child PID.
func Daemonize(exePath string, args []string) (int, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("daemonize: no args provided")
	}

	attr := &os.ProcAttr{
		Files: []*os.File{nil, nil, nil}, // Detach stdin/stdout/stderr
		Env:   os.Environ(),
	}

	proc, err := os.StartProcess(exePath, args, attr)
	if err != nil {
		return 0, fmt.Errorf("daemonize: start process: %w", err)
	}

	// Detach — don't wait for child
	proc.Release()

	return proc.Pid, nil
}

// ForegroundArgs builds the args to pass to Daemonize for a foreground listen
// subcommand detaching to background: tunnel run --name N [--log-file L].
func ForegroundArgs(name, logFile, endpoint, label string, yes bool) []string {
	args := []string{"tunnel", "run", "--name", name}
	if logFile != "" {
		args = append(args, "--log-file", logFile)
	}
	if endpoint != "" {
		args = append(args, "--endpoint", endpoint)
	}
	if label != "" {
		args = append(args, "--label", label)
	}
	if yes {
		args = append(args, "--yes")
	}
	return args
}

// SelfExe returns the path to the currently running executable.
func SelfExe() string {
	exe, err := os.Executable()
	if err != nil {
		return "datumctl-connect" // fallback
	}
	return exe
}
