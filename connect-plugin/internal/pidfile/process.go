package pidfile

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PIDAlive checks whether a process with the given PID is currently running.
// Uses OS-level checks:
//   - Unix: signals PID 0 (doesn't actually send a signal, just checks existence)
//   - Windows: uses tasklist /FI
// Returns false for invalid PIDs, errors, and non-existent processes.
func PIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return pidAlive(pid)
}

// RunningTunnel holds info about a discovered running tunnel process.
type RunningTunnel struct {
	Name       string
	GoPID      int
	RustPID    int
	StartTime  time.Time
	BinaryPath string
	Status     string // "Running", "Starting", "Degraded", "Zombie"
}

// ListRunningTunnels scans the tunnels directory and returns all tunnels
// with their current status based on PID file and process health.
func ListRunningTunnels(stateDir string) ([]RunningTunnel, error) {
	tunnelsDir := filepath.Join(stateDir, "tunnels")
	entries, err := os.ReadDir(tunnelsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var tunnels []RunningTunnel
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pid" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".pid")
		path := filepath.Join(tunnelsDir, entry.Name())

		pf, err := Read(path)
		if err != nil {
			continue
		}

		t := RunningTunnel{
			Name:       name,
			GoPID:      pf.GoPID,
			RustPID:    pf.RustPID,
			StartTime:  pf.StartTime,
			BinaryPath: pf.BinaryPath,
			Status:     computeTunnelStatus(pf),
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, nil
}

// computeTunnelStatus determines the tunnel status from a PidFile.
func computeTunnelStatus(pf *PidFile) string {
	goAlive := PIDAlive(pf.GoPID)
	rustAlive := PIDAlive(pf.RustPID)

	switch {
	case !goAlive && !rustAlive:
		return "Zombie"
	case goAlive && rustAlive:
		return "Running"
	case goAlive && !rustAlive:
		return "Degraded"
	case !goAlive && rustAlive:
		return "Zombie"
	default:
		return "Unknown"
	}
}
