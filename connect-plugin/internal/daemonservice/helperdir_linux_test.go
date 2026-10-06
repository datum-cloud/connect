//go:build linux

package daemonservice

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHelperExecutableUsesLibexecOnWritableUsr(t *testing.T) {
	original := usrReadOnly
	t.Cleanup(func() { usrReadOnly = original })
	usrReadOnly = func() bool { return false }
	if dir := helperExecutableDir(501); dir != "/usr/libexec/datum-connect/501" {
		t.Fatalf("Linux helper executable directory = %q", dir)
	}
}

func TestHelperExecutableAvoidsReadOnlyUsr(t *testing.T) {
	originalReadOnly, originalLocal := usrReadOnly, usrLocal
	t.Cleanup(func() { usrReadOnly, usrLocal = originalReadOnly, originalLocal })
	root := t.TempDir()
	target := filepath.Join(root, "var", "usrlocal")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	usrLocal = filepath.Join(root, "usr-local")
	if err := os.Symlink(target, usrLocal); err != nil {
		t.Fatal(err)
	}
	usrReadOnly = func() bool { return true }
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	// Trust checks reject symlinked ancestors, so the path must be resolved.
	if got, want := helperExecutableDir(501), filepath.Join(resolved, "sbin", "datum-connect", "501"); got != want {
		t.Fatalf("read-only /usr helper directory = %q, want %q", got, want)
	}
}
