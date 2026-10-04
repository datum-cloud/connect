package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
)

func interactiveFixture(t *testing.T) {
	t.Helper()
	oldInteractive, oldGuided := interactiveTerminal, guidedSetupEnabled
	interactiveTerminal = func(*cobra.Command) bool { return true }
	guidedSetupEnabled = func(*cobra.Command, *options) bool { return true }
	t.Cleanup(func() { interactiveTerminal, guidedSetupEnabled = oldInteractive, oldGuided })
	t.Setenv("DATUM_CONNECT_TOKEN", "")
	repo := t.TempDir()
	t.Setenv("DATUM_CONNECT_DIR", repo)
	if err := os.MkdirAll(filepath.Join(repo, "daemon_auth"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "daemon_auth/setup.token"), []byte("local-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	setSessionContextDirect(t)
}

func TestServeGuidedEnrollmentAndDownConsent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses explicit system setup")
	}
	for _, tt := range []struct {
		name, status, input string
		wantUp, wantServe   bool
	}{
		{"first run", `{}`, "yes\n", true, true},
		{"declined enrollment", `{}`, "no\n", false, false},
		{"already running", `{"running":true}`, "", false, true},
		{"down declined", `{"enrolled":true,"credential_configured":true}`, "n\n", false, false},
		{"down confirmed", `{"enrolled":true,"credential_configured":true}`, "y\n", true, true},
		{"failed enrollment remains explicit", `{"enrolled":true,"desired_up":true,"last_error":"revoked"}`, "y\n", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			interactiveFixture(t)
			var up, serve bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/v1/health" && r.Header.Get("Authorization") != "Bearer local-secret" {
					t.Error("missing local authorization")
				}
				switch r.URL.Path {
				case "/v1/health":
					io.WriteString(w, `{"status":"ok"}`)
				case "/v1/status":
					io.WriteString(w, tt.status)
				case "/v1/up":
					up = true
					var body map[string]any
					json.NewDecoder(r.Body).Decode(&body)
					if body["project"] != "demo" || body["datumctl_session"] == nil {
						t.Errorf("enrollment body = %#v", body)
					}
					io.WriteString(w, `{"running":true}`)
				case "/v1/services":
					serve = true
					var body map[string]any
					json.NewDecoder(r.Body).Decode(&body)
					if body["public"] != false {
						t.Error("setup changed private intent")
					}
					io.WriteString(w, `{"id":"s","connector":"alice","running":true,"endpoint":"localhost:8080","protocol":"tcp"}`)
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
				}
			}))
			defer server.Close()
			cmd := newServe(&options{baseURL: server.URL, timeout: time.Second})
			cmd.Flags().String("project", "demo", "")
			cmd.Flags().String("output", "table", "")
			cmd.SetIn(strings.NewReader(tt.input))
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"localhost:8080"})
			err := cmd.Execute()
			if (err == nil) != tt.wantServe || up != tt.wantUp || serve != tt.wantServe {
				t.Fatalf("up=%v serve=%v err=%v", up, serve, err)
			}
		})
	}
}

func TestGuidedSetupAllowsOnlyInteractiveLocalDaemonTargets(t *testing.T) {
	old := interactiveTerminal
	t.Cleanup(func() { interactiveTerminal = old })
	t.Setenv("DATUM_CONNECT_TOKEN", "")
	interactiveTerminal = func(*cobra.Command) bool { return true }
	localDaemonTargetAllowed := runtime.GOOS != "windows"
	for _, tt := range []struct {
		format, url, token, env string
		terminal                bool
		want                    bool
	}{
		{"json", connectapi.DefaultBaseURL, "", "", true, false},
		{"yaml", connectapi.DefaultBaseURL, "", "", true, false},
		{"table", "http://127.0.0.1:48888", "", "", true, localDaemonTargetAllowed},
		{"table", "http://localhost:48888", "", "", true, localDaemonTargetAllowed},
		{"table", "http://[::1]:48888", "", "", true, localDaemonTargetAllowed},
		{"table", "https://example.com", "", "", true, false},
		{"table", "http://127.0.0.1.evil.example", "", "", true, false},
		{"table", connectapi.DefaultBaseURL, "/scoped-token", "", true, false},
		{"table", connectapi.DefaultBaseURL, "", "scoped", true, false},
		{"table", connectapi.DefaultBaseURL, "", "", false, false},
	} {
		cmd := &cobra.Command{}
		cmd.Flags().String("output", tt.format, "")
		interactiveTerminal = func(*cobra.Command) bool { return tt.terminal }
		t.Setenv("DATUM_CONNECT_TOKEN", tt.env)
		if got := guidedSetup(cmd, &options{baseURL: tt.url, tokenFile: tt.token}); got != tt.want {
			t.Errorf("guided setup = %v, want %v: %#v", got, tt.want, tt)
		}
	}
}

func TestUnexpectedListenerNeverInstallsAService(t *testing.T) {
	interactiveFixture(t)
	old := ensureUserDaemon
	t.Cleanup(func() { ensureUserDaemon = old })
	ensureUserDaemon = func(context.Context, string, time.Duration, io.Writer, func(string) error) error {
		t.Fatal("attempted service install")
		return nil
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "not Connect", 503) }))
	defer server.Close()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := ensureDaemonForUp(cmd, &options{baseURL: server.URL, timeout: time.Second}); err == nil {
		t.Fatal("expected failure")
	}
}

func TestConfirmationConsumesOnlyOneLine(t *testing.T) {
	input := strings.NewReader("yes\nnext-picker-answer\n")
	cmd := &cobra.Command{}
	cmd.SetIn(input)
	cmd.SetErr(io.Discard)
	if err := confirmSetup(cmd, "Install?"); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(input)
	if string(rest) != "next-picker-answer\n" {
		t.Fatalf("consumed picker input: %q", rest)
	}
}

func TestHostRedispatchPreservesServeIntentAndRefreshesContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix host flow")
	}
	interactiveFixture(t)
	root := t.TempDir()
	helper := filepath.Join(root, "datumctl")
	log := filepath.Join(root, "args")
	t.Setenv("TEST_HOST_LOG", log)
	t.Setenv("DATUM_CREDENTIALS_HELPER", helper)
	t.Setenv("DATUM_CONNECT_GUIDED_LOGIN", "")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$TEST_HOST_LOG\"\nif [ -n \"$DATUM_SESSION\" ] || [ -n \"$DATUM_PROJECT\" ]; then exit 9; fi\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := newServe(&options{})
	cmd.SetContext(context.Background())
	cmd.Flags().String("project", "", "")
	if err := cmd.ParseFlags([]string{"localhost:8080", "--allow", "alice,bob", "--project", "demo"}); err != nil {
		t.Fatal(err)
	}
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := hostSetup(cmd, true); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	want := "login\nconnect\nserve\nlocalhost:8080\n--allow=alice,bob\n--project=demo\n"
	if string(data) != want {
		t.Fatalf("redispatch = %q", data)
	}
	t.Setenv("DATUM_CONNECT_GUIDED_LOGIN", "1")
	if err := hostSetup(cmd, true); err == nil {
		t.Fatal("recursive login accepted")
	}
}

func TestDeviceNamesAndShellSafeHints(t *testing.T) {
	for _, value := range []string{"alice-mac", "device1"} {
		if !validDeviceName(value) {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"", "../x", "-bad", "bad-", "UPPER", strings.Repeat("x", 64)} {
		if validDeviceName(value) {
			t.Fatal(value)
		}
	}
	if !validDeviceName(deviceNameHint()) {
		t.Fatal("invalid hostname hint")
	}
	var out bytes.Buffer
	cmd := &cobra.Command{Use: "serve"}
	cmd.SetOut(&out)
	cmd.Flags().String("project", "demo", "")
	if err := writeHuman(cmd, json.RawMessage(`{"id":"s","connector":"alice-mac","endpoint":"localhost:5353","desired_active":true,"running":true,"protocol":"udp"}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "datumctl connect dial alice-mac:5353 --bind 5353 --protocol udp --project demo") {
		t.Fatal(out.String())
	}
	if got := hostEnvironment([]string{"PATH=/bin", "DATUM_SESSION=old", "DATUM_PROJECT=p", "DATUM_CONNECT_GUIDED_LOGIN=1"}); !reflect.DeepEqual(got, []string{"PATH=/bin", "DATUM_CONNECT_GUIDED_LOGIN=1"}) {
		t.Fatal(got)
	}
}
