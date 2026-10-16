package daemonservice

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"

	"go.datum.net/datumctl-plugins/connect/internal/daemoninstall"
	"go.datum.net/datumctl-plugins/connect/internal/state"
)

// ForegroundExecutable finds datum-connectd for foreground modes that never
// install or contact a service. It prefers the binary next to the plugin or in
// PATH, then the same pinned, checksum-verified release download that guided
// setup uses. Local development builds never download an unrelated release.
func ForegroundExecutable(ctx context.Context, version string, progress io.Writer) (string, error) {
	if path, err := DiscoverExecutable(); err == nil {
		return path, nil
	}
	if !daemoninstall.PublishedRelease(version) {
		return "", fmt.Errorf("datum-connectd was not found next to the plugin or in PATH, and plugin version %q has no release to download it from", version)
	}
	root := filepath.Join(state.Dir(), "runtime")
	unlock, err := daemoninstall.Lock(root)
	if err != nil {
		return "", err
	}
	defer unlock()
	return daemoninstall.Installer{Root: root, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Progress: progress}.Acquire(ctx, version)
}
