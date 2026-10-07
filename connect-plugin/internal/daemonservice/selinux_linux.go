//go:build linux

package daemonservice

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// restoreSELinuxContext applies the policy's persistent file context to the
// helper. Files under /usr/libexec must have an executable type such as bin_t;
// copying a binary there does not reliably assign the right label on every
// filesystem or SELinux policy.
func restoreSELinuxContext(path string) error {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("check SELinux status: %w", err)
	}
	restorecon, err := exec.LookPath("restorecon")
	if err != nil {
		return fmt.Errorf("SELinux is enabled, but restorecon is unavailable; install policycoreutils and retry")
	}
	output, err := exec.Command(restorecon, "-F", filepath.Clean(path)).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return fmt.Errorf("apply SELinux file context: %w", err)
		}
		return fmt.Errorf("apply SELinux file context: %s: %w", message, err)
	}
	return nil
}
