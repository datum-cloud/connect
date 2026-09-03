//go:build !windows

package pidfile

import "syscall"

func pidAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
