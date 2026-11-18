package commands

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseBindAddress(t *testing.T) {
	for input, want := range map[string]string{
		"127.0.0.1":     "127.0.0.1",
		"0.0.0.0":       "0.0.0.0",
		"::":            "::",
		"[::]":          "::",
		"::1":           "::1",
		"[2001:db8::1]": "2001:db8::1",
		" 10.0.0.5 ":    "10.0.0.5",
	} {
		got, err := parseBindAddress(input)
		if err != nil || got != want {
			t.Errorf("parseBindAddress(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "localhost", "0.0.0.0:80", "fe80::1%eth0", "300.0.0.1", "[::"} {
		if got, err := parseBindAddress(input); err == nil {
			t.Errorf("parseBindAddress(%q) accepted %q", input, got)
		}
	}
}

func TestDialSendsBindAddressOnlyWhenRequested(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want any
	}{
		{"default stays loopback", []string{"peer:22", "--bind", "2222"}, nil},
		{"IPv4 unspecified", []string{"peer:80", "--bind", "8080", "--bind-address", "0.0.0.0"}, "0.0.0.0"},
		{"IPv6 unspecified", []string{"peer:80", "--bind", "8080", "--bind-address", "[::]"}, "::"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DATUM_CONNECT_TOKEN", "local-test-token")
			var body map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/v1/dials" {
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				io.WriteString(w, `{"connector":"peer","port":22,"bind":2222,"local_port":2222,"protocol":"tcp","desired_active":true,"running":true}`)
			}))
			defer server.Close()
			cmd := newDial(&options{baseURL: server.URL, timeout: time.Second})
			cmd.Flags().String("project", "demo", "")
			cmd.Flags().String("output", "json", "")
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(tt.args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			got, present := body["bind_address"]
			if tt.want == nil {
				if present {
					t.Fatalf("default dial sent bind_address %v", got)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("bind_address = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDialRejectsHostnameBindAddressBeforeRequest(t *testing.T) {
	cmd := newDial(&options{baseURL: "http://127.0.0.1:1", timeout: time.Second})
	cmd.Flags().String("project", "demo", "")
	cmd.Flags().String("output", "json", "")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"peer:22", "--bind-address", "localhost"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("accepted a host name as a bind address")
	}
}
