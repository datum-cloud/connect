package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestValidateEndpointIPv6(t *testing.T) {
	for _, endpoint := range []string{"localhost:8080", "127.0.0.1:443", "[::1]:9000"} {
		if err := validateEndpoint(endpoint); err != nil {
			t.Errorf("%s: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"::1:9000", "localhost", ":9000", "host:0", "host:99999"} {
		if err := validateEndpoint(endpoint); err == nil {
			t.Errorf("%s: expected error", endpoint)
		}
	}
}

func TestSplitConnector(t *testing.T) {
	tests := []struct {
		in, host string
		port     uint16
	}{
		{"connector-a:443", "connector-a", 443},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
	}
	for _, tt := range tests {
		host, port, err := splitConnector(tt.in)
		if err != nil || host != tt.host || port != tt.port {
			t.Errorf("%s = %q,%d,%v", tt.in, host, port, err)
		}
	}
}

func TestParseProtocol(t *testing.T) {
	for _, value := range []string{"tcp", "TCP", "udp", " UDP "} {
		if _, err := parseProtocol(value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	if _, err := parseProtocol("quic"); err == nil {
		t.Fatal("expected invalid protocol error")
	}
}

func TestDevNullIsNotInteractiveForSetupTokenFallback(t *testing.T) {
	t.Setenv("DATUM_CONNECT_TOKEN", "")
	repo := t.TempDir()
	t.Setenv("DATUM_CONNECT_DIR", repo)
	path := filepath.Join(repo, "daemon_auth", "setup.token")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("privileged-token"), 0600); err != nil {
		t.Fatal(err)
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	cmd := &cobra.Command{}
	cmd.SetIn(devNull)
	_, err = resolveToken(cmd, "")
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Fatalf("error = %v", err)
	}
}

func TestWriteJSONHonorsYAML(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("output", "yaml", "")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := writeJSON(cmd, json.RawMessage(`{"status":"ok","running":true}`)); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	if !strings.Contains(got, "status: ok") || !strings.Contains(got, "running: true") {
		t.Fatalf("YAML output = %q", got)
	}
}
