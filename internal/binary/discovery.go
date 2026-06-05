// Package binary provides functions to locate the datum-connect binary.
package binary

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Discover locates the datum-connect binary.
// Search order: (1) same directory as the running plugin binary,
// (2) PATH lookup. Returns error if not found.
func Discover() (string, error) {
	// TODO: Phase 2 — implement binary discovery
	// Search order: (1) same directory as the running plugin binary,
	// (2) PATH lookup.
	return "", nil
}

// binaryName returns the platform-appropriate binary name.
func binaryName() string {
	if os.Getenv("FAKE_DATUM_CONNECT") != "" {
		return "fake-datum-connect"
	}
	switch os.Getenv("DATUM_CONNECT_REPO") {
	case "local":
		return "datum-connect"
	default:
		return "datum-connect"
	}
}

// findNextToSelf returns the path to datum-connect in the same
// directory as the running binary, or "" if not found.
func findNextToSelf() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	path := filepath.Join(filepath.Dir(exe), binaryName())
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

// findInPath looks up datum-connect in PATH.
func findInPath() string {
	path, err := exec.LookPath(binaryName())
	if err != nil {
		return ""
	}
	return path
}
