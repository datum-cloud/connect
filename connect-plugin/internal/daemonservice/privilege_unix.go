//go:build darwin || linux

package daemonservice

import (
	"fmt"
	"os"
)

func requireSystemPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing a system daemon requires administrator privileges; rerun this command with sudo, or omit --system for an unprivileged user service")
	}
	return nil
}
