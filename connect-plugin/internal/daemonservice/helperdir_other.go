//go:build !linux

package daemonservice

func linuxHelperExecutableBase() string { return "/usr/libexec/datum-connect" }
