//go:build !windows

package daemonservice

import "os"

func secureServiceState(path string) error { return os.MkdirAll(path, 0700) }
func securePrivateFile(path string) error  { return os.Chmod(path, 0600) }
func windowsProgramData() string           { return `C:\ProgramData` }
