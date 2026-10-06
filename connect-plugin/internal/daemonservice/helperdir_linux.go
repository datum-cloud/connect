//go:build linux

package daemonservice

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Image-based distributions such as Fedora Silverblue mount /usr read-only.
// Their writable /usr/local is a symlink into /var, which the helper trust
// checks reject, so use the resolved path. SELinux labels the sbin and bin
// trees bin_t there, while /usr/local/libexec would be usr_t and not executable by systemd.
var (
	usrReadOnly = func() bool {
		var stat unix.Statfs_t
		return unix.Statfs("/usr", &stat) == nil && stat.Flags&unix.ST_RDONLY != 0
	}
	usrLocal = "/usr/local"
)

func linuxHelperExecutableBase() string {
	if !usrReadOnly() {
		return "/usr/libexec/datum-connect"
	}
	// Resolve sbin too: with Fedora's sbin merge it is itself a symlink to bin.
	if sbin, err := filepath.EvalSymlinks(filepath.Join(usrLocal, "sbin")); err == nil {
		return filepath.Join(sbin, "datum-connect")
	}
	local, err := filepath.EvalSymlinks(usrLocal)
	if err != nil {
		local = usrLocal
	}
	return filepath.Join(local, "sbin", "datum-connect")
}
