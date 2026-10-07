//go:build !linux

package daemonservice

func restoreSELinuxContext(string) error { return nil }
