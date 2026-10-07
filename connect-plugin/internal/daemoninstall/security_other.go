//go:build !darwin && !linux

package daemoninstall

import "fmt"

func checkPrivate(string, bool) error {
	return fmt.Errorf("automatic user installation requires macOS or Linux")
}
func checkParent(string) error {
	return fmt.Errorf("automatic user installation requires macOS or Linux")
}
