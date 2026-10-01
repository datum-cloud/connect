package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaemonCLIHTTPContract(t *testing.T) {
	type observed struct {
		Method, Path, Project, Authorization string
		Body                                 map[string]any
	}
	requests := make(chan observed, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry := observed{Method: r.Method, Path: r.URL.Path, Project: r.URL.Query().Get("project"), Authorization: r.Header.Get("Authorization")}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&entry.Body)
		}
		requests <- entry
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/services" {
			_, _ = io.WriteString(w, `{"id":"svc-1","public":false}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"up"}`)
	}))
	defer server.Close()

	bin := buildPlugin(t)
	cmd := exec.Command(bin, "--daemon-url", server.URL, "--project", "project-e2e", "--output", "json", "serve", "[::1]:8080", "--allow", "alice,bob")
	cmd.Env = append(os.Environ(), "DATUM_CONNECT_TOKEN=e2e-secret")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("serve: %v\n%s", err, out)
	}
	var response map[string]any
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	request := <-requests
	if request.Method != http.MethodPost || request.Path != "/v1/services" || request.Project != "project-e2e" {
		t.Fatalf("request = %#v", request)
	}
	if request.Authorization != "Bearer e2e-secret" {
		t.Fatalf("authorization = %q", request.Authorization)
	}
	if request.Body["endpoint"] != "[::1]:8080" || request.Body["public"] != false {
		t.Fatalf("body = %#v", request.Body)
	}
	if request.Body["protocol"] != "tcp" {
		t.Fatalf("protocol = %#v", request.Body["protocol"])
	}
	allow, ok := request.Body["allow"].([]any)
	if !ok || len(allow) != 2 {
		t.Fatalf("allow = %#v", request.Body["allow"])
	}
}

func TestUpPassesProjectAndAbsoluteCredentialPath(t *testing.T) {
	requests := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		requests <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"up"}`)
	}))
	defer server.Close()
	credential := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credential, []byte(`{"type":"connector"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(buildPlugin(t), "--daemon-url", server.URL, "--project", "p", "up", "--credentials-file", credential)
	cmd.Env = append(os.Environ(), "DATUM_CONNECT_TOKEN=token")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("up: %v\n%s", err, out)
	}
	body := <-requests
	if body["project"] != "p" || body["credentials_file"] != credential {
		t.Fatalf("body = %#v", body)
	}
}

func TestServeDefaultsPrivateWithEmptyAllowArray(t *testing.T) {
	requests := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		requests <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"svc-private"}`)
	}))
	defer server.Close()
	cmd := exec.Command(buildPlugin(t), "--daemon-url", server.URL, "--project", "p", "serve", "localhost:8080")
	cmd.Env = append(os.Environ(), "DATUM_CONNECT_TOKEN=token")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("serve: %v\n%s", err, out)
	}
	body := <-requests
	if body["public"] != false {
		t.Fatalf("public = %#v", body["public"])
	}
	allow, ok := body["allow"].([]any)
	if !ok || len(allow) != 0 {
		t.Fatalf("allow must be an empty JSON array, got %#v", body["allow"])
	}
}

func TestVerboseErrorHasRequestIDButNoToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-ID", "req-123")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"scope denied"}`)
	}))
	defer server.Close()
	cmd := exec.Command(buildPlugin(t), "--daemon-url", server.URL, "--project", "p", "--verbose", "status")
	cmd.Env = append(os.Environ(), "DATUM_CONNECT_TOKEN=do-not-print-me")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure: %s", out)
	}
	text := string(out)
	if !strings.Contains(text, "req-123") || !strings.Contains(text, "HTTP 403") {
		t.Fatalf("missing diagnostics: %s", out)
	}
	if strings.Contains(text, "do-not-print-me") {
		t.Fatalf("token leaked: %s", out)
	}
}

func TestServeBeforeSetupGivesCLIRecovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-ID", "req-private")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"project has not been configured","code":"project_not_configured"}`)
	}))
	defer server.Close()
	cmd := exec.Command(buildPlugin(t), "serve", "localhost:800", "--daemon-url", server.URL, "--project", "first-run")
	cmd.Env = append(os.Environ(), "DATUM_CONNECT_TOKEN=do-not-print-me")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure: %s", out)
	}
	for _, want := range []string{`project "first-run"`, `datumctl connect up --project "first-run"`, "datumctl login", "up --help"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %q: %s", want, out)
		}
	}
	for _, unwanted := range []string{"HTTP", "/v1/", "req-private", "do-not-print-me"} {
		if strings.Contains(string(out), unwanted) {
			t.Fatalf("leaked %q: %s", unwanted, out)
		}
	}
}
