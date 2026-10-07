package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/services" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("project"); got != "project-a" {
			t.Errorf("project = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("authorization = %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["public"] != false || body["endpoint"] != "[::1]:8080" {
			t.Errorf("body = %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"service-1"}`))
	}))
	defer server.Close()

	client, err := New(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Request(context.Background(), http.MethodPost, "/v1/services", "project-a", map[string]any{
		"endpoint": "[::1]:8080", "public": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"id":"service-1"}` {
		t.Fatalf("response = %s", got)
	}
}

func TestRequestSurfacesJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"error":"network operations are not supported"}`))
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", time.Second)
	_, err := client.Request(context.Background(), http.MethodPost, "/v1/networks", "p", map[string]string{"network": "n"})
	if err == nil || err.Error() != "daemon: network operations are not supported (HTTP 501)" {
		t.Fatalf("error = %v", err)
	}
}

func TestRequestCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	client, _ := New(server.URL, "", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Request(ctx, http.MethodGet, "/v1/health", "", nil); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestRequestTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	client, _ := New(server.URL, "", 10*time.Millisecond)
	_, err := client.Request(context.Background(), http.MethodGet, "/v1/health", "", nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewRejectsNonLoopbackAndURLDecorations(t *testing.T) {
	for _, raw := range []string{
		"http://example.com:47780", "http://127.0.0.1.evil:47780",
		"http://user:pass@localhost:47780", "http://localhost:47780/v1",
		"http://localhost:47780?token=bad", "file:///tmp/daemon.sock",
	} {
		if _, err := New(raw, "token", time.Second); err == nil {
			t.Errorf("%q: expected rejection", raw)
		}
	}
	for _, raw := range []string{"http://localhost:47780", "http://127.0.0.1:47780", "http://[::1]:47780"} {
		if _, err := New(raw, "token", time.Second); err != nil {
			t.Errorf("%q: %v", raw, err)
		}
	}
	if _, err := New(DefaultBaseURL, "token", 0); err == nil {
		t.Fatal("zero timeout must be rejected")
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	receivedAuthorization := make(chan string, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		receivedAuthorization <- r.Header.Get("Authorization")
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	client, err := New(origin.URL, "must-not-leak", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), http.MethodGet, "/v1/status", "p", nil); err == nil {
		t.Fatal("expected redirect response to fail")
	}
	select {
	case got := <-receivedAuthorization:
		t.Fatalf("redirect followed and authorization leaked: %q", got)
	default:
	}
}
