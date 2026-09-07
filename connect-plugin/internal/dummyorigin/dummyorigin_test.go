package dummyorigin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestServeAndObserveRequest(t *testing.T) {
	var gotMethod, gotPath string
	srv, err := Start("localhost:0", func(method, path string) {
		gotMethod, gotPath = method, path
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	resp, err := http.Get("http://" + srv.Addr() + "/hello/world")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var payload struct {
		Message string    `json:"message"`
		Method  string    `json:"method"`
		Path    string    `json:"path"`
		Time    time.Time `json:"time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if payload.Method != "GET" {
		t.Errorf("expected method 'GET' in payload, got %q", payload.Method)
	}
	if payload.Path != "/hello/world" {
		t.Errorf("expected path '/hello/world' in payload, got %q", payload.Path)
	}
	if payload.Message == "" {
		t.Error("expected a non-empty message in payload")
	}
	if payload.Time.IsZero() {
		t.Error("expected a non-zero time in payload")
	}

	if gotMethod != "GET" || gotPath != "/hello/world" {
		t.Errorf("onRequest callback got (%q, %q), want (\"GET\", \"/hello/world\")", gotMethod, gotPath)
	}
}

func TestStartBindError(t *testing.T) {
	srv, err := Start("localhost:0", nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Binding the exact same address again should fail.
	if _, err := Start(srv.Addr(), nil); err == nil {
		t.Error("expected an error binding an already-in-use address")
	}
}
