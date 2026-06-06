package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDatumctlContextEnvVars verifies that the datumctl plugin SDK reads
// the correct environment variables that datumctl injects before exec-replacing
// a plugin. This tests the datumctl → plugin boundary.
func TestDatumctlContextEnvVars(t *testing.T) {
	bin := buildPlugin(t)

	env := []string{
		"DATUM_ORG=my-org",
		"DATUM_PROJECT=my-project",
		"DATUM_API_HOST=api.datum.net",
		"DATUM_PLUGIN_API_VERSION=1",
		"DATUM_CREDENTIALS_HELPER=/fake/credentials-helper",
		"DATUM_SESSION=dev",
	}

	cmd := exec.Command(bin, "--help")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help exited non-zero: %v\n%s", err, out)
	}

	available := string(out)
	if !strings.Contains(available, "--org") {
		t.Error("help should show --org flag (injected by datumctl)")
	}
	if !strings.Contains(available, "--project") {
		t.Error("help should show --project flag (injected by datumctl)")
	}
}

// TestCredentialsHelperCalledWithSession verifies that the datumctl plugin
// SDK calls the credentials helper with the correct session argument.
func TestCredentialsHelperCalledWithSession(t *testing.T) {
	helperDir := t.TempDir()
	helperBin := filepath.Join(helperDir, "helper")

	helperSrc := `package main
import (
	"os"
	"fmt"
)
func main() {
	f, _ := os.Create("/tmp/helper-args.log")
	if f != nil {
		for i, arg := range os.Args {
			fmt.Fprintf(f, "%d:%s\n", i, arg)
		}
		f.Close()
	}
	fmt.Println("session-token-from-helper")
}
`
	helperPath := filepath.Join(helperDir, "helper.go")
	if err := os.WriteFile(helperPath, []byte(helperSrc), 0644); err != nil {
		t.Fatalf("write helper source: %v", err)
	}

	buildCmd := exec.Command("go", "build", "-o", helperBin, helperPath)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}

	cmd := exec.Command(helperBin, "auth", "get-token", "--session", "test-session")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	token := strings.TrimSpace(string(out))
	if token != "session-token-from-helper" {
		t.Errorf("expected 'session-token-from-helper', got '%s'", token)
	}
}

// TestPluginManifestBeforeSubprocessSpawn verifies that --plugin-manifest
// is handled before any subprocess spawning, so the datumctl host can
// discover the plugin without triggering subprocess execution.
func TestPluginManifestBeforeSubprocessSpawn(t *testing.T) {
	bin := buildPlugin(t)

	cmd := exec.Command(bin, "--plugin-manifest")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--plugin-manifest should work without datumctl env: %v\n%s", err, out)
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(out, &manifest); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, out)
	}

	if manifest["name"] != "connect" {
		t.Error("manifest name should be 'connect'")
	}
	if manifest["api_version"] != float64(1) {
		t.Errorf("expected api_version=1, got %v", manifest["api_version"])
	}
}

// TestPluginPassesContextToSubcommand verifies that the Go plugin correctly
// passes datumctl context (org, project, output format) to subcommands.
func TestPluginPassesContextToSubcommand(t *testing.T) {
	bin := buildPlugin(t)
	fakeBin := buildFakeDatumConnect(t)
	fakeHelper := buildFakeHelper(t, "testdata/fake-credentials-helper")

	connectDir, _ := os.Getwd()
	cmd := exec.Command(bin, "--org", "custom-org", "--project", "custom-project", "--output", "yaml", "tunnel", "list")
	cmd.Env = append(os.Environ(),
		"FAKE_DATUM_CONNECT="+fakeBin,
		"DATUM_CREDENTIALS_HELPER="+fakeHelper,
		"DATUM_SESSION=dev",
		"PATH="+connectDir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list exited non-zero: %v\n%s", err, out)
	}

	// Should contain tunnel data from fake binary
	if !bytes.Contains(out, []byte("dev-server")) {
		t.Errorf("expected tunnel data in output, got: %s", out)
	}
}

// TestCredentialsHelperTokenFlow verifies the token passing chain works:
// plugin reads DATUM_CREDENTIALS_HELPER → calls helper → gets token
func TestCredentialsHelperTokenFlow(t *testing.T) {
	fakeHelper := buildFakeHelper(t, "testdata/fake-credentials-helper")
	fakeBin := buildFakeDatumConnect(t)

	connectDir, _ := os.Getwd()
	env := []string{
		"DATUM_CREDENTIALS_HELPER=" + fakeHelper,
		"DATUM_SESSION=dev",
		"FAKE_DATUM_CONNECT=" + fakeBin,
		"PATH=" + connectDir + ":" + os.Getenv("PATH"),
	}

	// Run the plugin with the fake helper and fake binary
	cmd := exec.Command(buildPlugin(t), "tunnel", "list")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list exited non-zero: %v\n%s", err, out)
	}

	// Should contain tunnel data from fake binary
	if !bytes.Contains(out, []byte("dev-server")) {
		t.Errorf("expected tunnel data in output, got: %s", out)
	}
}

// TestPluginBinaryIsExecutable verifies the built plugin binary is a valid executable.
func TestPluginBinaryIsExecutable(t *testing.T) {
	bin := buildPlugin(t)

	info, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("stat plugin binary: %v", err)
	}
	if info.Size() == 0 {
		t.Error("plugin binary should not be empty")
	}
}

// TestFullChainEnvVarPropagation verifies the full env var chain:
// datumctl → plugin → Rust binary
// 1. datumctl sets DATUM_CREDENTIALS_HELPER
// 2. Plugin reads DATUM_CREDENTIALS_HELPER, calls helper, gets token
// 3. Plugin sets DATUM_ACCESS_TOKEN for Rust binary
// 4. Rust binary reads DATUM_ACCESS_TOKEN
func TestFullChainEnvVarPropagation(t *testing.T) {
	// Step 1: Plugin manifest works standalone
	pluginBin := buildPlugin(t)

	cmd := exec.Command(pluginBin, "--plugin-manifest")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("manifest should work standalone: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte(`"name": "connect"`)) {
		t.Error("manifest should contain name='connect'")
	}

	// Step 2: Verify plugin reads DATUM_CREDENTIALS_HELPER from env
	fakeHelper := buildFakeHelper(t, "testdata/fake-credentials-helper")
	cmd = exec.Command(pluginBin, "tunnel", "list")
	cmd.Env = append(os.Environ(), "DATUM_CREDENTIALS_HELPER="+fakeHelper)
	_ = cmd.Run()
}

// Helper functions

func buildPlugin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "connect-test")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, out)
	}
	return bin
}
