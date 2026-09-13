//go:build windows

package pidfile

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// pidAlive checks whether a process with the given PID is currently
// running, via `tasklist /FI`. See process_unix.go for why this lives in
// its own build-tag-gated file rather than a single cross-platform function.
func pidAlive(pid int) bool {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), strconv.Itoa(pid))
}
