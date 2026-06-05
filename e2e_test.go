package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPluginManifestEmitsValidJSON(t *testing.T) {
	// PLUG-01: --plugin-manifest emits valid JSON and exits 0
	cmd := exec.Command("./connect", "--plugin-manifest")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--plugin-manifest exited non-zero: %v\n%s", err, out)
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(out, &manifest); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, out)
	}

	if manifest["name"] != "connect" {
		t.Errorf("expected name='connect', got '%v'", manifest["name"])
	}
	if manifest["version"] != "v0.1.0" {
		t.Errorf("expected version='v0.1.0', got '%v'", manifest["version"])
	}
	if manifest["description"] != "Manage Datum Connect tunnels" {
		t.Errorf("expected description='Manage Datum Connect tunnels', got '%v'", manifest["description"])
	}
}

func TestPluginManifestExitsBeforeCobraParses(t *testing.T) {
	// --plugin-manifest must be handled before cobra parses args
	// so even invalid cobra flags should not prevent manifest output
	cmd := exec.Command("./connect", "--plugin-manifest", "--invalid-cobra-flag")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--plugin-manifest should exit 0 even with invalid flags: %v\n%s", err, out)
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(out, &manifest); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, out)
	}
	if manifest["name"] != "connect" {
		t.Error("manifest name should be 'connect'")
	}
}

func TestAll12SubcommandsScaffolded(t *testing.T) {
	// PLUG-06: All 12 subcommands scaffolded as stubs
	cmd := exec.Command("./connect", "tunnel", "--help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tunnel help exited non-zero: %v\n%s", err, out)
	}

	expectedSubcommands := []string{
		"list", "listen", "update", "delete",
		"ps", "stop", "logs", "status",
		"install", "uninstall", "start", "run",
	}

	available := string(out)
	for _, sub := range expectedSubcommands {
		if !strings.Contains(available, sub) {
			t.Errorf("tunnel help should list subcommand '%s'", sub)
		}
	}
}

func TestSubcommandStubsPrintNotImplemented(t *testing.T) {
	// Each stub prints "not implemented" with its target phase
	stubs := map[string]string{
		"list":        "Phase 4",
		"listen":      "Phase 4",
		"update":      "Phase 4",
		"delete":      "Phase 4",
		"ps":          "Phase 5",
		"stop":        "Phase 5",
		"logs":        "Phase 5",
		"status":      "Phase 5",
		"install":     "Phase 6",
		"uninstall":   "Phase 6",
		"start":       "Phase 6",
		"run":         "Phase 6",
	}

	for subcmd, expectedPhase := range stubs {
		t.Run(subcmd, func(t *testing.T) {
			cmd := exec.Command("./connect", "tunnel", subcmd)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s exited non-zero: %v\n%s", subcmd, err, out)
			}
			if !bytes.Contains(out, []byte("not implemented")) {
				t.Errorf("%s should print 'not implemented'", subcmd)
			}
			if !bytes.Contains(out, []byte(expectedPhase)) {
				t.Errorf("%s should reference %s", subcmd, expectedPhase)
			}
		})
	}
}

func TestFakeDatumConnectListJSON(t *testing.T) {
	// Test fakes are functional and testable
	fakeBin := buildFakeBinary(t, "testdata/fake-datum-connect")
	cmd := exec.Command(fakeBin, "--json", "list")
	cmd.Env = append(os.Environ(), "DATUM_ACCESS_TOKEN=test-token")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fake-datum-connect list --json exited non-zero: %v\n%s", err, out)
	}

	var tunnels []map[string]interface{}
	if err := json.Unmarshal(out, &tunnels); err != nil {
		t.Fatalf("fake output is not valid JSON: %v\n%s", err, out)
	}
	if len(tunnels) == 0 {
		t.Error("expected at least one tunnel in list output")
	}
}

func TestFakeDatumConnectDeleteJSON(t *testing.T) {
	fakeBin := buildFakeBinary(t, "testdata/fake-datum-connect")
	cmd := exec.Command(fakeBin, "--json", "delete")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fake-datum-connect delete --json exited non-zero: %v\n%s", err, out)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("delete output is not valid JSON: %v\n%s", err, out)
	}
	if deleted, ok := result["deleted"].(bool); !ok || !deleted {
		t.Error("delete should return {\"deleted\": true}")
	}
}

func TestFakeCredentialsHelperDefaultMode(t *testing.T) {
	fakeBin := buildFakeHelper(t, "testdata/fake-credentials-helper")
	cmd := exec.Command(fakeBin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fake-credentials-helper exited non-zero: %v\n%s", err, out)
	}

	token := strings.TrimSpace(string(out))
	if token == "" {
		t.Error("default mode should output a token")
	}
}

func TestFakeCredentialsHelperRefusesToken(t *testing.T) {
	fakeBin := buildFakeHelper(t, "testdata/fake-credentials-helper")
	cmd := exec.Command(fakeBin)
	cmd.Env = append(os.Environ(), "FAKE_HELPER_MODE=refuses-token")
	err := cmd.Run()
	if err == nil {
		t.Error("refuses-token mode should exit non-zero")
	}
}

func TestFakeCredentialsHelperSessionDependent(t *testing.T) {
	fakeBin := buildFakeHelper(t, "testdata/fake-credentials-helper")

	// Should succeed with matching session
	cmd := exec.Command(fakeBin, "--session", "test-session")
	cmd.Env = append(os.Environ(), "FAKE_HELPER_MODE=session-dependent")
	if err := cmd.Run(); err != nil {
		t.Fatalf("session-dependent with correct session should succeed: %v", err)
	}

	// Should fail with wrong session
	cmd = exec.Command(fakeBin, "--session", "wrong-session")
	cmd.Env = append(os.Environ(), "FAKE_HELPER_MODE=session-dependent")
	if err := cmd.Run(); err == nil {
		t.Error("session-dependent with wrong session should fail")
	}
}

func TestBuildScriptExists(t *testing.T) {
	// Build script exists and is executable
	info, err := os.Stat("scripts/build.sh")
	if err != nil {
		t.Fatalf("scripts/build.sh should exist: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("scripts/build.sh should be executable")
	}
}

func TestReleaseScriptExists(t *testing.T) {
	// Release script exists and is executable
	info, err := os.Stat("scripts/release.sh")
	if err != nil {
		t.Fatalf("scripts/release.sh should exist: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("scripts/release.sh should be executable")
	}
}

func buildFakeBinary(t *testing.T, src string) string {
	t.Helper()
	bin := src + "-test"
	cmd := exec.Command("go", "build", "-o", bin, "./"+src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build %s: %v\n%s", src, err, out)
	}
	t.Cleanup(func() { os.Remove(bin) })
	return bin
}

func buildFakeHelper(t *testing.T, src string) string {
	t.Helper()
	bin := src + "-test"
	cmd := exec.Command("go", "build", "-o", bin, "./"+src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build %s: %v\n%s", src, err, out)
	}
	t.Cleanup(func() { os.Remove(bin) })
	return bin
}
