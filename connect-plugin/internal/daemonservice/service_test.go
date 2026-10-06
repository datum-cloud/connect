package daemonservice

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kardianos/service"
)

func TestWaitReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	if err := waitReady(context.Background(), srv.URL, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestWaitReadyDoesNotAcceptUnhealthyOrHang(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"starting"}`)) }))
	defer srv.Close()
	started := time.Now()
	if err := waitReady(context.Background(), srv.URL, 30*time.Millisecond); err == nil {
		t.Fatal("unhealthy daemon considered ready")
	}
	if time.Since(started) > time.Second {
		t.Fatal("readiness timeout exceeded")
	}
}

func TestLaunchdJobRunningUsesStructuredPrintOutput(t *testing.T) {
	if !launchdJobRunning(`state = running
pid = 35177
`) {
		t.Fatal("launchd process with a PID was not recognized as running")
	}
	for _, output := range []string{"state = waiting", "service not found", "pid = 0"} {
		if launchdJobRunning(output) {
			t.Fatalf("launchd output %q was recognized as running", output)
		}
	}
}

func TestDaemonAPIHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	if !daemonAPIHealthy(context.Background(), srv.URL) {
		t.Fatal("healthy daemon API was reported unreachable")
	}
}

func TestRunServiceActionTimesOut(t *testing.T) {
	blocked := make(chan struct{})
	err := runServiceAction(context.Background(), nil, func(service.Service) error {
		<-blocked
		return nil
	}, 10*time.Millisecond)
	close(blocked)
	if err == nil {
		t.Fatal("blocked service action did not time out")
	}
}

func TestServiceConfigIsExplicitAndScoped(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "datum-connect-daemon")
	if err := os.WriteFile(exe, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	_, cfg, err := makeService(false, exe, 47781, "/private/credentials.json", "/private/ip.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyConfig(cfg, false); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Option["UserService"]; got != true {
		t.Fatalf("UserService = %#v", got)
	}
	if !argumentPair(cfg.Arguments, "--credentials-file", "/private/credentials.json") ||
		!argumentPair(cfg.Arguments, "--local-ip-config", "/private/ip.json") {
		t.Fatalf("args = %#v", cfg.Arguments)
	}
	if runtime.GOOS == "windows" && cfg.Arguments[len(cfg.Arguments)-1] != "--windows-service" {
		t.Fatalf("Windows service args = %#v", cfg.Arguments)
	}
	if cfg.Arguments[4] != "--log-file" || cfg.Arguments[5] != filepath.Join(serviceStateDir(false), "daemon.log") {
		t.Fatalf("log args = %#v", cfg.Arguments)
	}
	if runtime.GOOS == "linux" && len(cfg.Dependencies) == 0 {
		t.Fatal("systemd config lacks network dependency")
	}
}

func argumentPair(arguments []string, name, value string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name && arguments[index+1] == value {
			return true
		}
	}
	return false
}

func TestValidateLocalIPConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip.json")
	if err := os.WriteFile(path, []byte(`{"bindings":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateLocalIPConfig("relative.json", true, true); err == nil {
		t.Fatal("relative config accepted")
	}
	if _, err := validateLocalIPConfig(path, false, true); err == nil {
		t.Fatal("unprivileged service config accepted")
	}
	if runtime.GOOS == "darwin" {
		if _, err := validateLocalIPConfig(path, true, false); err == nil {
			t.Fatal("macOS system IP service accepted without credentials")
		}
	}
	if got, err := validateLocalIPConfig(path, true, true); err != nil || got != path {
		t.Fatalf("validateLocalIPConfig() = %q, %v", got, err)
	}
}

func TestCopyCredentialValidatesAndSecures(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "input.json")
	destination := filepath.Join(dir, "state", "credentials.json")
	if err := os.Mkdir(filepath.Dir(destination), 0700); err != nil {
		t.Fatal(err)
	}
	data := `{"type":"connector","project_id":"p","api_endpoint":"https://api.example","token_uri":"https://auth.example/token","client_id":"c","refresh_token":"secret"}`
	if err := os.WriteFile(source, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyCredential(source, destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	got, _ := os.ReadFile(destination)
	if string(got) != data {
		t.Fatal("credential content changed")
	}
}

func TestCopyCredentialRejectsUnknownType(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(source, []byte(`{"type":"password"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyCredential(source, filepath.Join(dir, "out.json")); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestCopyCredentialRequiresStandardServiceAccountIdentityFields(t *testing.T) {
	dir := t.TempDir()
	valid := map[string]string{
		"type":           "datum_service_account",
		"project_id":     "project",
		"client_id":      "provider-client-id",
		"client_email":   "connector@example.invalid",
		"private_key_id": "provider-key-id",
		"private_key":    "private-key",
	}
	for _, field := range []string{"client_id", "client_email", "private_key_id"} {
		t.Run(field, func(t *testing.T) {
			shape := maps.Clone(valid)
			delete(shape, field)
			data, err := json.Marshal(shape)
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(dir, field+".json")
			if err := os.WriteFile(source, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := copyCredential(source, filepath.Join(dir, field+"-out.json")); err == nil {
				t.Fatalf("service-account credentials without %s were accepted", field)
			}
		})
	}
}
