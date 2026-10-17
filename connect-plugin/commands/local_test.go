package commands

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestLocalTarget(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		host    string
		port    uint16
		portSet bool
		want    string
		wantErr string
	}{
		{name: "port flag", host: "localhost", port: 9999, portSet: true, want: "localhost:9999"},
		{name: "host and port", host: "127.0.0.1", port: 3000, portSet: true, want: "127.0.0.1:3000"},
		{name: "positional", args: []string{"[::1]:8080"}, want: "[::1]:8080"},
		{name: "both", args: []string{"localhost:1"}, port: 2, portSet: true, wantErr: "not both"},
		{name: "neither", wantErr: "--port"},
		{name: "zero port", host: "localhost", portSet: true, wantErr: "--port"},
		{name: "listen address", args: []string{"0.0.0.0:80"}, wantErr: "listen address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := localTarget(tt.args, tt.host, tt.port, tt.portSet)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestDescribePath(t *testing.T) {
	ms := func(v int64) *int64 { return &v }
	tests := []struct {
		event foregroundEvent
		want  string
	}{
		{foregroundEvent{Path: "direct", Remote: "[2001:db8::1]:4433", RTTMs: ms(12)}, "direct to [2001:db8::1]:4433, 12 ms"},
		{foregroundEvent{Path: "relay", Remote: "https://relay.example./", RTTMs: ms(150)}, "relayed via https://relay.example./, 150 ms"},
		{foregroundEvent{Path: "unknown"}, "path unknown"},
	}
	for _, tt := range tests {
		if got := describePath(tt.event); got != tt.want {
			t.Errorf("describePath = %q, want %q", got, tt.want)
		}
	}
}

func TestLocalCommandShowsDevicePaths(t *testing.T) {
	stdout := `{"event":"share_ready","ticket":"DCSHARE2T"}
{"event":"share_paired","peer":"66ed43143f88520ba7cae1b7f7eb10b9","name":"pixel"}
{"event":"share_path","peer":"66ed43143f88520ba7cae1b7f7eb10b9","path":"relay","remote":"https://relay.example./","rtt_ms":150}
{"event":"share_path","peer":"66ed43143f88520ba7cae1b7f7eb10b9","path":"direct","remote":"[2001:db8::1]:4433","rtt_ms":12}`
	exe, _ := fakeDaemon(t, stdout, "", 0)
	out, err := runCommand(t, exe, "local", "--port", "9999")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"  pixel: relayed via https://relay.example./, 150 ms", "  pixel: direct to [2001:db8::1]:4433, 12 ms"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestShareName(t *testing.T) {
	if got, err := shareName("", "localhost:9999", false); err != nil || got != deviceNameHint()+":9999" {
		t.Fatalf("default = %q, %v", got, err)
	}
	if got, err := shareName("  API  ", "localhost:9999", true); err != nil || got != "API" {
		t.Fatalf("trimmed = %q, %v", got, err)
	}
	for _, bad := range []string{" ", "a\x1b[31m", strings.Repeat("x", 65)} {
		if _, err := shareName(bad, "localhost:1", true); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestForegroundEnvDropsCredentials(t *testing.T) {
	env := foregroundEnv([]string{"PATH=/bin", "DATUM_SESSION=s", "DATUM_CREDENTIALS_HELPER=/x", "DATUM_CONNECT_TOKEN=t"}, false)
	for _, entry := range env {
		if strings.HasPrefix(entry, "DATUM_") {
			t.Fatalf("credential variable passed to child: %s", entry)
		}
	}
	if !slices.Contains(env, "RUST_LOG=warn") || !slices.Contains(env, "PATH=/bin") {
		t.Fatalf("env = %v", env)
	}
	if env := foregroundEnv([]string{"RUST_LOG=debug"}, true); !slices.Equal(env, []string{"RUST_LOG=debug"}) {
		t.Fatalf("explicit RUST_LOG must win: %v", env)
	}
}

func TestLogTailLastError(t *testing.T) {
	tail := &logTail{}
	io.WriteString(tail, `{"fields":{"message":"relay_ready"}}`+"\n")
	io.WriteString(tail, `{"fields":{"message":"projectless_failed","error":"pairing failed: invalid secret"}}`+"\n")
	if got := tail.lastError(); got != "pairing failed: invalid secret" {
		t.Fatalf("lastError = %q", got)
	}
	usage := &logTail{}
	io.WriteString(usage, "error: unexpected argument 'local' found\n\nUsage: datum-connectd --repo <REPO>")
	if got := usage.lastError(); !strings.Contains(got, "unexpected argument 'local'") {
		t.Fatalf("lastError = %q", got)
	}
	clap := &logTail{}
	io.WriteString(clap, "error: invalid value 'DCSHARE2x' for '<TICKET>': malformed share ticket\n\nFor more information, try '--help'.\n")
	if got := clap.lastError(); got != "invalid value 'DCSHARE2x' for '<TICKET>': malformed share ticket" {
		t.Fatalf("lastError = %q", got)
	}
}

// fakeDaemon writes a datum-connectd stand-in that records its arguments and
// prints the given stdout and stderr.
func fakeDaemon(t *testing.T, stdout, stderr string, exitCode int) (exe, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake daemon")
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	exe = filepath.Join(dir, "datum-connectd")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nenv > " + argsFile + ".env\ncat <<'OUT'\n" + stdout + "\nOUT\ncat >&2 <<'ERR'\n" + stderr + "\nERR\nexit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(exe, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return exe, argsFile
}

func runCommand(t *testing.T, exe string, args ...string) (string, error) {
	t.Helper()
	old := foregroundExecutable
	foregroundExecutable = func(context.Context, string, io.Writer) (string, error) { return exe, nil }
	t.Cleanup(func() { foregroundExecutable = old })
	t.Setenv("DATUM_SESSION", "should-not-leak")
	root := &cobra.Command{Use: "connect"}
	root.PersistentFlags().StringP("output", "o", "table", "")
	root.PersistentFlags().String("project", "", "")
	Add(root)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestLocalCommandRunsProjectless(t *testing.T) {
	stdout := `{"event":"share_ready","endpoint_id":"ab","target":"127.0.0.1:9999","ticket":"DCSHARE2TICKET"}
{"event":"share_paired","peer":"66ed43143f88520ba7cae1b7f7eb10b9","name":"pixel"}`
	exe, argsFile := fakeDaemon(t, stdout, "", 0)
	out, err := runCommand(t, exe, "local", "--port", "9999", "--name", "API dev server")
	if err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(argsFile)
	want := []string{"local", "localhost:9999", "--max-peers", "4", "--name", "API dev server"}
	if got := strings.Split(strings.TrimSpace(string(args)), "\n"); !slices.Equal(got, want) {
		t.Fatalf("daemon args = %q", got)
	}
	env, _ := os.ReadFile(argsFile + ".env")
	if strings.Contains(string(env), "DATUM_SESSION") {
		t.Fatal("DATUM_SESSION leaked to the child")
	}
	for _, want := range []string{"Sharing localhost:9999 as \"API dev server\"", "datumctl connect dial DCSHARE2TICKET --bind 9999", "✓ Paired pixel (66ed43143f88…)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestLocalCommandJSONPassesEventsThrough(t *testing.T) {
	stdout := `{"event":"share_ready","ticket":"DCSHARE2T"}`
	exe, _ := fakeDaemon(t, stdout, "", 0)
	out, err := runCommand(t, exe, "local", "localhost:80", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != stdout {
		t.Fatalf("output = %q", out)
	}
}

func TestTicketDialReportsChildError(t *testing.T) {
	stderr := `{"fields":{"message":"projectless_failed","error":"pairing failed: invalid secret"}}`
	exe, argsFile := fakeDaemon(t, "", stderr, 1)
	_, err := runCommand(t, exe, "dial", "DCSHARE2XYZ", "--bind", "8888")
	if err == nil || err.Error() != "pairing failed: invalid secret" {
		t.Fatalf("err = %v", err)
	}
	args, _ := os.ReadFile(argsFile)
	got := strings.Fields(string(args))
	if len(got) < 4 || !slices.Equal(got[:4], []string{"local-dial", "DCSHARE2XYZ", "--bind", "127.0.0.1:8888"}) {
		t.Fatalf("daemon args = %v", got)
	}
}

func TestTicketDialRejectsUDP(t *testing.T) {
	exe, _ := fakeDaemon(t, "", "", 0)
	_, err := runCommand(t, exe, "dial", "DCSHARE2XYZ", "--protocol", "udp")
	if err == nil || !strings.Contains(err.Error(), "TCP only") {
		t.Fatalf("err = %v", err)
	}
}
