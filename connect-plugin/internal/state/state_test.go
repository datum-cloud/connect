package state

import (
	"path/filepath"
	"testing"
)

func TestDaemonDirectoryAndTokenPaths(t *testing.T) {
	root := t.TempDir()
	t.Setenv("DATUM_CONNECT_STATE_DIR", root)
	t.Setenv("DATUM_CONNECT_DIR", "")
	if Dir() != root {
		t.Fatalf("state directory ignores override: %s", Dir())
	}
	if DaemonDir() != filepath.Join(root, "daemon") {
		t.Fatalf("unexpected daemon directory: %s", DaemonDir())
	}
	if SetupTokenPath() != filepath.Join(root, "daemon", "daemon_auth", "setup.token") {
		t.Fatalf("unexpected token path: %s", SetupTokenPath())
	}
	explicit := t.TempDir()
	t.Setenv("DATUM_CONNECT_DIR", explicit)
	if DaemonDir() != explicit {
		t.Fatalf("daemon directory ignores override: %s", DaemonDir())
	}
}
