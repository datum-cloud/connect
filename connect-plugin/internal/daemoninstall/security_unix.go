//go:build darwin || linux

package daemoninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func checkPrivate(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && (!info.Mode().IsRegular() || st.Nlink != 1)) {
		return fmt.Errorf("refuse unsafe daemon installation path %s: must be private, owned by this user, and not a link", path)
	}
	return checkParent(filepath.Dir(path))
}

func checkParent(dir string) error {
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (info.Mode()&os.ModeSymlink != 0 && st.Uid != 0) {
			return fmt.Errorf("refuse non-system directory alias %s", current)
		}
		stickyRoot := st.Uid == 0 && info.Mode()&os.ModeSticky != 0
		if info.Mode()&os.ModeSymlink == 0 && (!info.IsDir() || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (info.Mode().Perm()&0022 != 0 && !stickyRoot)) {
			return fmt.Errorf("refuse unsafe installation parent %s", current)
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	// Canonicalize root-owned macOS directory aliases without accepting an
	// attacker-writable directory as an executable's ancestor.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	for current := resolved; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		stickyRoot := ok && st.Uid == 0 && info.Mode()&os.ModeSticky != 0
		if !ok || !info.IsDir() || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (info.Mode().Perm()&0022 != 0 && !stickyRoot) {
			return fmt.Errorf("refuse unsafe installation parent %s", current)
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}
