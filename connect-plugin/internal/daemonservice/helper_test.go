package daemonservice

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHelperExplainsItsPrivilegeBoundary(t *testing.T) {
	if (runtime.GOOS != "darwin" && runtime.GOOS != "linux") || os.Geteuid() == 0 {
		t.Skip("requires an ordinary Unix user")
	}
	cmd := HelperCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"install", "--uid", "501"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "sudo") || strings.Contains(err.Error(), "--system") {
		t.Fatalf("unhelpful administrator guidance: %v", err)
	}
}

func TestHelperServiceContainsNoUserCredentials(t *testing.T) {
	cfg := helperServiceConfig(501, "/Library/PrivilegedHelperTools/datum-connect-network-helper")
	if cfg.Option["UserService"] != false || !strings.HasSuffix(cfg.Name, "-501") {
		t.Fatalf("wrong scope: %#v", cfg)
	}
	args := strings.Join(cfg.Arguments, " ")
	if strings.Contains(args, "credentials") || strings.Contains(args, "session") || strings.Contains(args, "repo") {
		t.Fatalf("credentials leaked into helper: %s", args)
	}
	if !argumentPair(cfg.Arguments, "--socket", filepath.Join(helperStateDir(501), "helper.sock")) {
		t.Fatalf("wrong socket: %#v", cfg.Arguments)
	}
}

func TestHelperExecutableIsOutsideLinuxStateDirectory(t *testing.T) {
	dir := helperExecutableDir(501)
	if runtime.GOOS == "linux" {
		if dir != "/usr/libexec/datum-connect/501" {
			t.Fatalf("Linux helper executable directory = %q", dir)
		}
		if strings.HasPrefix(dir, helperStateDir(501)) {
			t.Fatalf("Linux helper executable remains under mutable state: %q", dir)
		}
	} else if dir != helperStateDir(501) {
		t.Fatalf("non-Linux helper path changed unexpectedly: %q", dir)
	}
}

func TestUserIPConfigRequiresHelperAndPeerOnlyApprovals(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Unix helper")
	}
	path := filepath.Join(t.TempDir(), "ip.json")
	for _, test := range []struct {
		data  string
		valid bool
	}{
		{`{"network_helper":"/private/helper.sock","peer_bindings":[{}]}`, true},
		{`{"network_helper":"relative.sock","peer_bindings":[{}]}`, false},
		{`{"network_helper":"/private/helper.sock","bindings":[{}],"peer_bindings":[{}]}`, false},
		{`{"network_helper":"/private/helper.sock","peer_bindings":[]}`, false},
	} {
		if err := os.WriteFile(path, []byte(test.data), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := validateLocalIPConfig(path, false, false)
		if (err == nil) != test.valid {
			t.Fatalf("%s: %v", test.data, err)
		}
	}
}
