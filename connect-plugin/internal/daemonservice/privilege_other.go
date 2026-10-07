//go:build !darwin && !linux && !windows

package daemonservice

func requireSystemPrivileges() error { return nil }
