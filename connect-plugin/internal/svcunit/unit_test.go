package svcunit

import (
	"reflect"
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

// TestServiceArgs asserts the Phase 13 CLI contract for service units.
//
// Resolution table Item #7: `tunnel run` accepts only --name. All runtime
// config (label, endpoint, project, session, credentials_helper_path) is
// resolved by `run` from the persisted YAML config (svcconfig.Load) and the
// server, not from CLI flags. If a future phase re-introduces CLI-passed
// runtime config, update ServiceArgs AND this test together.
func TestServiceArgs(t *testing.T) {
	cfg := svcconfig.TunnelConfig{
		Name:     "test-tun",
		Label:    "test",
		Endpoint: "localhost:8080",
		Session:  "my-session",
	}
	args := ServiceArgs(cfg)
	want := []string{"tunnel", "run", "--name", "test-tun"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("ServiceArgs() = %v, want %v", args, want)
	}

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--name test-tun") {
		t.Errorf("args should contain --name, got: %s", joined)
	}
	// Runtime config is YAML/server-driven; these CLI flags must not appear.
	for _, flag := range []string{"--endpoint", "--session", "--label", "--yes"} {
		if strings.Contains(joined, flag) {
			t.Errorf("args should not contain %s (runtime config is YAML/server-driven), got: %s", flag, joined)
		}
	}
}

// TestBuildConfig_EnvVarsEmptyWithoutHelper asserts the Phase 13 pass-through
// env contract: buildConfig sets NO per-service DATUM_* env vars. Runtime
// config (DATUM_CONNECT_DIR, DATUM_SESSION) arrives via the plugin's
// os.Environ() pass-through (Phase 11.5) or the persisted YAML; per-service
// isolation was removed in Phase 13 (D-01).
func TestBuildConfig_EnvVarsEmptyWithoutHelper(t *testing.T) {
	sc, err := buildConfig(svcconfig.TunnelConfig{Name: "my-tunnel"}, "/usr/local/bin/datumctl-connect")
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}
	if sc.EnvVars == nil {
		t.Fatal("buildConfig() EnvVars is nil; want an initialized (possibly empty) map")
	}
	if len(sc.EnvVars) != 0 {
		t.Errorf("buildConfig() EnvVars should be empty without CredentialsHelperPath; got %v", sc.EnvVars)
	}
	if _, ok := sc.EnvVars["DATUM_CONNECT_DIR"]; ok {
		t.Errorf("EnvVars must not set DATUM_CONNECT_DIR (pass-through design), got %v", sc.EnvVars)
	}
}

// TestBuildConfig_CredentialsHelperEnvVar asserts the one env var buildConfig
// DOES set: DATUM_CREDENTIALS_HELPER, only when a path is configured.
func TestBuildConfig_CredentialsHelperEnvVar(t *testing.T) {
	sc, err := buildConfig(
		svcconfig.TunnelConfig{Name: "my-tunnel", CredentialsHelperPath: "/usr/bin/datum-cred-helper"},
		"/usr/local/bin/datumctl-connect",
	)
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}
	want := map[string]string{"DATUM_CREDENTIALS_HELPER": "/usr/bin/datum-cred-helper"}
	if !reflect.DeepEqual(sc.EnvVars, want) {
		t.Errorf("EnvVars = %v, want %v", sc.EnvVars, want)
	}
}

// TestServiceArgs_NoLabel documents that ServiceArgs never emits --label: the
// label is resolved at run time from the server/YAML. Keeping the name asserts
// the runtime-args contract even as TunnelConfig gains more persisted fields.
func TestServiceArgs_NoLabel(t *testing.T) {
	cfg := svcconfig.TunnelConfig{Name: "minimal"}
	args := ServiceArgs(cfg)
	// The only flag is --name; a new persisted field must not leak into args.
	want := []string{"tunnel", "run", "--name", "minimal"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("ServiceArgs() = %v, want %v", args, want)
	}
}
