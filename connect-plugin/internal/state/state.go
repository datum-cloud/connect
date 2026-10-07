// Package state provides cross-platform plugin state directory resolution.
//
// State directory contains the daemon's credentials, desired state, and logs.
// DATUM_CONNECT_STATE_DIR overrides the platform default when explicitly set.
// Paths follow platform conventions:
//
//	linux:   $XDG_STATE_HOME/datumctl/connect (default ~/.local/state/datumctl/connect)
//	darwin:  ~/Library/Application Support/datumctl/connect
//	windows: %LOCALAPPDATA%/datumctl/connect
package state

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// Dir returns the plugin state base directory.
func Dir() string {
	if override := os.Getenv("DATUM_CONNECT_STATE_DIR"); override != "" {
		return override
	}

	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "datumctl", "connect")
	case "darwin":
		u, err := user.Current()
		if err != nil {
			return filepath.Join(".", "datumctl", "connect")
		}
		return filepath.Join(u.HomeDir, "Library", "Application Support", "datumctl", "connect")
	default:
		xdg := os.Getenv("XDG_STATE_HOME")
		if xdg == "" {
			xdg = filepath.Join(os.Getenv("HOME"), ".local", "state")
		}
		return filepath.Join(xdg, "datumctl", "connect")
	}
}

// DaemonDir is the dedicated state directory used by the successor daemon.
func DaemonDir() string {
	if repo := os.Getenv("DATUM_CONNECT_DIR"); repo != "" {
		return repo
	}
	return filepath.Join(Dir(), "daemon")
}

// SetupTokenPath is the daemon's privileged local setup credential.
func SetupTokenPath() string {
	return filepath.Join(DaemonDir(), "daemon_auth", "setup.token")
}
