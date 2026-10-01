package daemoninstall

import (
	"fmt"
	"os"
	"path/filepath"
)

// Lock serializes service bootstrap as well as acquisition. Never steal a
// possibly live installer's lock. An interrupted installation needs inspection.
func Lock(root string) (func(), error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := privateDirectory(root); err != nil {
		return nil, err
	}
	lock := filepath.Join(root, "setup.lock")
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(err) {
		return nil, fmt.Errorf("Connect setup is already in progress; retry when it finishes. If setup was interrupted, confirm no installer is running before removing %s", lock)
	}
	if err != nil {
		return nil, err
	}
	f.Close()
	return func() { _ = os.Remove(lock) }, nil
}
