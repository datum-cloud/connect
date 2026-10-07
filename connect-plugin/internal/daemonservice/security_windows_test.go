package daemonservice

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSecureServiceStateProtectsDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Datum", "Connect")
	if err := secureServiceState(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("private state DACL still inherits from its parent")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("private state has no DACL: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if owner.String() != admins.String() {
		t.Fatalf("owner = %s, want %s", owner, admins)
	}
}

func TestSecureServiceStateRejectsReparsePoint(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating Windows symlink requires host permission: %v", err)
	}
	if err := secureServiceState(link); err == nil {
		t.Fatal("reparse point accepted as private state")
	}
}

func TestSecureServiceStateRejectsHardlinkedFile(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(state, "credentials.json")
	if err := os.WriteFile(first, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, filepath.Join(state, "alias.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := secureServiceState(state); err == nil {
		t.Fatal("hard-linked state file accepted")
	}
}
