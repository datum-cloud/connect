// Package pidfile provides functions to manage PID files.
package pidfile

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Write writes a PID file at path with format:
// <pid>\n<start-time-rfc3339>\n<binary-path>\n
func Write(path string, pid int, startTime time.Time, binaryPath string) error {
	// TODO: Phase 3 — implement PID file writing
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	content := fmt.Sprintf("%d\n%s\n%s\n", pid, startTime.Format(time.RFC3339), binaryPath)
	return os.WriteFile(path, []byte(content), 0644)
}

// Read reads and parses a PID file. Returns pid, startTime, binaryPath.
func Read(path string) (int, time.Time, string, error) {
	// TODO: Phase 3 — implement PID file reading
	_, err := os.ReadFile(path)
	if err != nil {
		return 0, time.Time{}, "", err
	}
	// Parse format: pid\nstart-time\nbinary-path\n
	return 0, time.Time{}, "", nil
}

// Exists checks if a PID file exists at path.
func Exists(path string) bool {
	// TODO: Phase 3 — implement PID file existence check
	_, err := os.Stat(path)
	return err == nil
}
