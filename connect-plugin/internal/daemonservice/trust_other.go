//go:build !darwin && !linux && !windows

package daemonservice

func validatePrivilegedExecutable(string) error { return nil }
