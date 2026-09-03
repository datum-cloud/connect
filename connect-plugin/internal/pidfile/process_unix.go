//go:build !windows

package pidfile

import "syscall"

func pidAlive(pid int) bool {
	// Signal 0 checks existence without sending a signal
	return syscall.Kill(pid, 0) == nil
}
