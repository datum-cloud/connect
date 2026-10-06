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
	usrReadOnly = func() bool { return true }
	for _, test := range []struct {
		name string
		sbin string // "dir", "symlink" (to bin, Fedora's sbin merge), or "" (absent)
		want string
	}{
		{name: "sbin directory", sbin: "dir", want: "sbin"},
		{name: "sbin merged into bin", sbin: "symlink", want: "bin"},
		{name: "sbin absent", want: "sbin"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "var", "usrlocal")
			if err := os.MkdirAll(filepath.Join(target, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			switch test.sbin {
			case "dir":
				err = os.Mkdir(filepath.Join(target, "sbin"), 0o755)
			case "symlink":
				err = os.Symlink("bin", filepath.Join(target, "sbin"))
			}
			if err != nil {
				t.Fatal(err)
			}
			usrLocal = filepath.Join(root, "usr-local")
			if err := os.Symlink(target, usrLocal); err != nil {
				t.Fatal(err)
			}
			got := helperExecutableDir(501)
			if want := filepath.Join(target, test.want, "datum-connect", "501"); got != want {
				t.Fatalf("read-only /usr helper directory = %q, want %q", got, want)
			}
			// Trust checks reject any symlinked ancestor of the helper.
			for current := got; current != root; current = filepath.Dir(current) {
				if info, err := os.Lstat(current); err == nil && info.Mode()&os.ModeSymlink != 0 {
					t.Fatalf("helper directory %q has symlinked ancestor %q", got, current)
				}
			}
		})
	}
}
