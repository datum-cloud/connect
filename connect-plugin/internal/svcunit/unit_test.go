package svcunit

import (
	"strings"
	"testing"

	"go.datum.net/datumctl-plugins/connect/internal/svcconfig"
)

func TestServiceName(t *testing.T) {
	name := ServiceName("my-tunnel")
	expected := "datumctl-connect-my-tunnel"
	if name != expected {
		t.Errorf("ServiceName = %q, want %q", name, expected)
	}
}

func TestServiceArgs(t *testing.T) {
	// Phase 13: tunnel run accepts only --name; endpoint/session/credentials
	// come from the YAML config, not CLI flags.
	cfg := svcconfig.TunnelConfig{
		Name:     "test-tun",
		Label:    "test",
		Endpoint: "localhost:8080",
		Session:  "my-session",
	}
	args := ServiceArgs(cfg)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--name test-tun") {
		t.Errorf("args should contain --name, got: %s", joined)
	}
	if strings.Contains(joined, "--endpoint") {
		t.Errorf("args should not contain --endpoint (comes from YAML), got: %s", joined)
	}
	if strings.Contains(joined, "--session") {
		t.Errorf("args should not contain --session (comes from YAML), got: %s", joined)
	}
	if strings.Contains(joined, "--yes") {
		t.Errorf("args should not contain --yes (removed in Phase 13), got: %s", joined)
	}
}

func TestServiceArgs_NoLabel(t *testing.T) {
	cfg := svcconfig.TunnelConfig{
		Name:     "minimal",
		Endpoint: "localhost:8080",
		Session:  "sess",
	}
	args := ServiceArgs(cfg)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--label") {
		t.Errorf("args should not contain --label for empty label, got: %s", joined)
	}
}

func TestBuildConfig_NoDatumConnectDirEnvVar(t *testing.T) {
	// Phase 13: DATUM_CONNECT_DIR is NOT injected by buildConfig — it arrives
	// via the plugin's os.Environ() pass-through. Per-service isolation removed.
	cfg := svcconfig.TunnelConfig{
		Name:     "my-tunnel",
		Endpoint: "localhost:8080",
	}
	sc, err := buildConfig(cfg, "/usr/local/bin/datumctl-connect")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}
	if _, ok := sc.EnvVars["DATUM_CONNECT_DIR"]; ok {
		t.Errorf("EnvVars should not contain DATUM_CONNECT_DIR (set by environment, not unit file)")
	}
}

func TestBuildConfig_EmptyEnvVarsWithNoHelper(t *testing.T) {
	// Without a credentials helper path, EnvVars should be empty.
	sc, err := buildConfig(svcconfig.TunnelConfig{Name: "x"}, "bin")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}
	if len(sc.EnvVars) != 0 {
		t.Errorf("EnvVars should be empty when no credentials helper; got %d: %v",
			len(sc.EnvVars), sc.EnvVars)
	}
}

func TestBuildConfig_SetsCredentialsHelper(t *testing.T) {
	cfg := svcconfig.TunnelConfig{
		Name:                  "x",
		CredentialsHelperPath: "/usr/local/bin/my-helper",
	}
	sc, err := buildConfig(cfg, "bin")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}
	got, ok := sc.EnvVars["DATUM_CREDENTIALS_HELPER"]
	if !ok {
		t.Fatalf("EnvVars missing DATUM_CREDENTIALS_HELPER; got %v", sc.EnvVars)
	}
	if got != "/usr/local/bin/my-helper" {
		t.Errorf("DATUM_CREDENTIALS_HELPER = %q, want %q", got, "/usr/local/bin/my-helper")
	}
	if len(sc.EnvVars) != 1 {
		t.Errorf("EnvVars should have exactly 1 entry; got %d: %v", len(sc.EnvVars), sc.EnvVars)
	}
}
