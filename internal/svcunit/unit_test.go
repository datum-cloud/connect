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
	if !strings.Contains(joined, "--endpoint localhost:8080") {
		t.Errorf("args should contain --endpoint, got: %s", joined)
	}
	if !strings.Contains(joined, "--session my-session") {
		t.Errorf("args should contain --session, got: %s", joined)
	}
	if !strings.Contains(joined, "--yes") {
		t.Errorf("args should contain --yes, got: %s", joined)
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
