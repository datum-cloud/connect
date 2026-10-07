//go:build darwin || linux

package daemonservice

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validatePrivilegedExecutable(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse unsafe system-service executable path %s: %s and its parent directories must be root-owned, non-symlink, and not writable by group or other users", path, current)
		}
		if current == string(filepath.Separator) {
			break
		}
	}
	return nil
}
