//go:build windows

package pidfile

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func pidAlive(pid int) bool {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), strconv.Itoa(pid))
}
