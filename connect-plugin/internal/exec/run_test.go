package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func buildFakeBinary(t *testing.T, src string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test source")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	binName := "fake-datum-connect-test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	bin := filepath.Join(t.TempDir(), binName)
	cmd := exec.Command("go", "build", "-o", bin, "./"+src)
	cmd.Dir = moduleRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build %s: %v\n%s", src, err, out)
	}
	return bin
}

func TestRunWithValidBinary(t *testing.T) {
	fakeBin := buildFakeBinary(t, "testdata/fake-datum-connect")
	env := []string{"DATUM_ACCESS_TOKEN=test-token"}

	result, err := Run(context.Background(), fakeBin, []string{"--json", "list"}, env, OutputModeJSON)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	var tunnels []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(result.Stdout, &tunnels); err != nil {
		t.Fatalf("stdout is not valid tunnel JSON: %v\n%s", err, result.Stdout)
	}
	if len(tunnels) != 2 || tunnels[0].ID != "tun-123" {
		t.Fatalf("unexpected tunnels: %#v", tunnels)
	}
}

func TestRunWithNonZeroExit(t *testing.T) {
	fakeBin := buildFakeBinary(t, "testdata/fake-datum-connect")
	env := []string{"FAKE_DUMMY_MODE=child-crash"}

	result, err := Run(context.Background(), fakeBin, []string{"--json", "list"}, env, OutputModeJSON)
	if err != nil {
		t.Fatalf("Run() returned error (expected nil for non-zero exit): %v", err)
	}
	if result.ExitCode != 1 {
		t.Errorf("expected child exit code 1, got %d", result.ExitCode)
	}
}

func TestRunWithNotFoundBinary(t *testing.T) {
	_, err := Run(context.Background(), "/nonexistent/binary", []string{"list"}, nil, OutputModeJSON)
	if err == nil {
		t.Fatal("expected error for non-existent binary, got nil")
	}
	if !strings.Contains(err.Error(), "failed to start") {
		t.Errorf("expected 'failed to start' in error, got: %v", err)
	}
}

func TestRunWithOutputModeYAML(t *testing.T) {
	fakeBin := buildFakeBinary(t, "testdata/fake-datum-connect")
	env := []string{"DATUM_ACCESS_TOKEN=test-token"}

	result, err := Run(context.Background(), fakeBin, []string{"--json", "list"}, env, OutputModeYAML)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	var tunnels []struct {
		ID string `yaml:"id"`
	}
	if err := yaml.Unmarshal(result.Stdout, &tunnels); err != nil {
		t.Fatalf("stdout is not valid tunnel YAML: %v\n%s", err, result.Stdout)
	}
	if len(tunnels) != 2 || tunnels[0].ID != "tun-123" {
		t.Fatalf("unexpected tunnels: %#v", tunnels)
	}
}

func TestRunWithOutputModeTableLeavesJSONForCaller(t *testing.T) {
	fakeBin := buildFakeBinary(t, "testdata/fake-datum-connect")
	env := []string{"DATUM_ACCESS_TOKEN=test-token"}

	result, err := Run(context.Background(), fakeBin, []string{"--json", "list"}, env, OutputModeTable)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	jsonResult, err := Run(context.Background(), fakeBin, []string{"--json", "list"}, env, OutputModeJSON)
	if err != nil {
		t.Fatalf("Run() in JSON mode returned error: %v", err)
	}
	if !bytes.Equal(result.Stdout, jsonResult.Stdout) {
		t.Fatalf("table mode changed caller-owned JSON:\n table: %s\n  json: %s", result.Stdout, jsonResult.Stdout)
	}
}

func TestParseTypedMessage(t *testing.T) {
	// Verify ParseTypedMessage handles typed messages correctly.
	// Rust-side contract guarantees every message has a "type" field.
	// Malformed JSON returns false; caller treats as fatal error.
	tests := []struct {
		name       string
		line       []byte
		expectType string
		expectOk   bool
	}{
		{
			name:       "ready message",
			line:       []byte(`{"type":"ready","id":"tun-123","status":"ready"}`),
			expectType: "ready",
			expectOk:   true,
		},
		{
			name:       "error message",
			line:       []byte(`{"type":"error","message":"something failed"}`),
			expectType: "error",
			expectOk:   true,
		},
		{
			name:       "heartbeat message without message field",
			line:       []byte(`{"type":"heartbeat"}`),
			expectType: "heartbeat",
			expectOk:   true,
		},
		{
			name:       "malformed JSON",
			line:       []byte(`{invalid json}`),
			expectType: "",
			expectOk:   false,
		},
		{
			name:       "empty line",
			line:       []byte(``),
			expectType: "",
			expectOk:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, ok := ParseTypedMessage(tt.line)
			if ok != tt.expectOk {
				t.Errorf("ParseTypedMessage(%q) ok=%v, want %v", tt.line, ok, tt.expectOk)
			}
			if tt.expectOk && msg.Type != tt.expectType {
				t.Errorf("ParseTypedMessage(%q) type=%q, want %q", tt.line, msg.Type, tt.expectType)
			}
			// Verify no panic on messages without "message" field
			if tt.expectOk && tt.name == "heartbeat message without message field" {
				if msg.Message != "" {
					t.Errorf("expected empty message for heartbeat, got %q", msg.Message)
				}
			}
		})
	}
}
