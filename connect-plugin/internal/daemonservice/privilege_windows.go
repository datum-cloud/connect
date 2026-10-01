package daemonservice

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func requireSystemPrivileges() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("installing the Windows service requires administrator privileges; rerun this command from an elevated terminal")
	}
	return nil
}
