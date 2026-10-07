package commands

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func setSessionContext(t *testing.T) string {
	t.Helper()
	helper := setSessionContextDirect(t)
	link := filepath.Join(filepath.Dir(helper), "datumctl-link")
	if err := os.Symlink(helper, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATUM_CREDENTIALS_HELPER", link)
	canonical, err := filepath.EvalSymlinks(helper)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func setSessionContextDirect(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	helper := filepath.Join(dir, "datumctl")
	if runtime.GOOS == "windows" {
		helper += ".exe"
	}
	// Deliberately not executable: collecting host metadata must not run it.
	if err := os.WriteFile(helper, []byte("not a token helper"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATUM_CREDENTIALS_HELPER", helper)
	t.Setenv("DATUM_SESSION", "personal")
	t.Setenv("DATUM_API_HOST", "api.datum.net")
	return helper
}

func TestHostSessionPinsNamedSessionAndResolvesHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the local Windows service does not use host-session OIDC")
	}
	helper := setSessionContext(t)
	session, err := hostSession()
	if err != nil {
		t.Fatal(err)
	}
	if session.HelperPath != helper || session.Session != "personal" || session.APIEndpoint != "https://api.datum.net" {
		t.Fatalf("session = %#v", session)
	}
}

func TestHostSessionRejectsMissingNameAndUnsafeEndpoints(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the local Windows service does not use host-session OIDC")
	}
	for _, test := range []struct{ env, value string }{
		{"DATUM_SESSION", ""},
		{"DATUM_SESSION", " "},
		{"DATUM_CREDENTIALS_HELPER", "/missing/helper"},
		{"DATUM_CREDENTIALS_HELPER", "./datumctl"},
		{"DATUM_API_HOST", "http://api.datum.net"},
		{"DATUM_API_HOST", "https://user:secret@api.datum.net"},
		{"DATUM_API_HOST", "https://api.datum.net/path"},
		{"DATUM_API_HOST", "https://api.datum.net?secret=x"},
	} {
		t.Run(test.env+test.value, func(t *testing.T) {
			setSessionContext(t)
			t.Setenv(test.env, test.value)
			if _, err := hostSession(); err == nil {
				t.Fatal("expected invalid host context")
			}
		})
	}
}

func TestUpAuthenticationSelection(t *testing.T) {
	setSessionContextDirect(t)
	for _, auth := range []string{"auto", "oidc", "stored"} {
		body := map[string]any{}
		if err := addUpAuthenticationForPlatform(body, auth, "", "linux"); err != nil {
			t.Fatal(err)
		}
		if body["auth"] != auth {
			t.Fatalf("auth missing: %#v", body)
		}
		_, session := body["datumctl_session"]
		if session != (auth != "stored") {
			t.Fatalf("%s session presence = %v", auth, session)
		}
	}
	for _, auth := range []string{"oidc", "stored", "unknown"} {
		if err := addUpAuthenticationForPlatform(map[string]any{}, auth, "credentials.json", "linux"); err == nil {
			t.Errorf("%s with credentials file accepted", auth)
		}
	}
	body := map[string]any{}
	if err := addUpAuthenticationForPlatform(body, "auto", "credentials.json", "linux"); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["datumctl_session"]; exists {
		t.Fatal("credential file import also sent host session")
	}
}

func TestWindowsUpAuthenticationRejectsOIDC(t *testing.T) {
	body := map[string]any{}
	err := addUpAuthenticationForPlatform(body, "oidc", "", "windows")
	if err == nil || !strings.Contains(err.Error(), "LocalSystem") || !strings.Contains(err.Error(), "--credentials-file") {
		t.Fatalf("Windows OIDC error = %v", err)
	}
	body = map[string]any{}
	if err := addUpAuthenticationForPlatform(body, "auto", "", "windows"); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["datumctl_session"]; exists {
		t.Fatal("Windows auto authentication sent a host session")
	}
}

func TestAutoUpCanResumeWithoutUsableHostContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the local Windows service does not use host-session OIDC")
	}
	setSessionContext(t)
	t.Setenv("DATUM_SESSION", "")
	body := map[string]any{}
	if err := addUpAuthenticationForPlatform(body, "auto", "", "linux"); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["datumctl_session"]; exists {
		t.Fatal("sent empty host session")
	}
	err := addUpAuthenticationForPlatform(map[string]any{}, "oidc", "", "linux")
	if err == nil || !strings.Contains(err.Error(), "datumctl login") || !strings.Contains(err.Error(), "through datumctl") {
		t.Fatalf("explicit OIDC error = %v", err)
	}
}

func TestUpSendsSessionMetadataWithoutTokens(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the local Windows service rejects host-session OIDC")
	}
	helper := setSessionContext(t)
	t.Setenv("DATUM_CONNECT_TOKEN", "local-daemon-token")
	requests := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/up" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		requests <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"project":"p","running":true,"credential_configured":true}`))
	}))
	defer server.Close()
	cmd := newUp(&options{baseURL: server.URL, timeout: time.Second})
	cmd.Flags().String("project", "p", "")
	cmd.Flags().String("output", "json", "")
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--auth", "oidc"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	body := <-requests
	if body["auth"] != "oidc" || body["project"] != "p" || body["name_hint"] == "" || len(body) != 4 {
		t.Fatalf("unexpected request body = %#v", body)
	}
	session, ok := body["datumctl_session"].(map[string]any)
	if !ok || len(session) != 3 || session["session"] != "personal" || session["helper_path"] != helper || session["api_endpoint"] != "https://api.datum.net" {
		t.Fatalf("session = %#v", body["datumctl_session"])
	}
}

func TestSetupCommandOmitsCurrentProject(t *testing.T) {
	t.Setenv("DATUM_PROJECT", "current")
	if got := setupCommand("current"); got != "datumctl connect up" {
		t.Fatal(got)
	}
	if got := setupCommand("other"); got != `datumctl connect up --project "other"` {
		t.Fatal(got)
	}
}
