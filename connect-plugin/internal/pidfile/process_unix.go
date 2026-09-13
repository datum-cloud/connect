//go:build !windows

package pidfile

import "syscall"

// pidAlive checks whether a process with the given PID is currently
// running, by signaling PID 0 — which doesn't actually send a signal, just
// checks existence. Isolated in its own build-tag-gated file (paired with
// process_windows.go) because syscall.Kill doesn't exist in Go's Windows
// syscall package — a single cross-platform pidAlive that references both
// implementations unconditionally breaks native Windows compilation
// entirely, which is exactly the bug this split fixes.
func pidAlive(pid int) bool {
	// Signal 0 checks existence without sending a signal
	return syscall.Kill(pid, 0) == nil
}
