package commands

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type bootstrapTransport func(*http.Request) (*http.Response, error)

func (f bootstrapTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise the real serve command and HTTP client without sockets or native
// service changes. Acquisition/security and service transitions have separate
// fixture tests; this proves the CLI continues through setup in one invocation.
func TestServeBootstrapFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows requires explicit system setup")
	}
	for _, decline := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "declined"}[decline], func(t *testing.T) {
			interactiveFixture(t)
			oldTransport, oldEnsure := http.DefaultTransport, ensureUserDaemon
			t.Cleanup(func() { http.DefaultTransport, ensureUserDaemon = oldTransport, oldEnsure })
			var steps []string
			http.DefaultTransport = bootstrapTransport(func(r *http.Request) (*http.Response, error) {
				steps = append(steps, r.URL.Path)
				if r.URL.Path == "/v1/health" {
					return nil, syscall.ECONNREFUSED
				}
				if r.Header.Get("Authorization") != "Bearer local-secret" {
					t.Fatal("missing local authorization")
				}
				body := `{}`
				switch r.URL.Path {
				case "/v1/status":
				case "/v1/up":
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if payload["project"] != "demo" || payload["datumctl_session"] == nil {
						t.Fatal(payload)
					}
				case "/v1/services":
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if payload["public"] != false || payload["endpoint"] != "localhost:8080" {
						t.Fatal(payload)
					}
					body = `{"id":"s","connector":"alice","running":true,"endpoint":"localhost:8080","protocol":"tcp"}`
				default:
					t.Fatalf("unexpected API call %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			ensureUserDaemon = func(ctx context.Context, version string, timeout time.Duration, progress io.Writer, confirm func(string) error) error {
				steps = append(steps, "bootstrap")
				if version != "v1.0.0-preview.1" {
					t.Fatalf("lost plugin version: %q", version)
				}
				if err := confirm("Install daemon?"); err != nil {
					return err
				}
				steps = append(steps, "ready")
				return nil
			}
			cmd := newServe(&options{baseURL: "http://127.0.0.1:47780", timeout: time.Second})
			cmd.Version = "v1.0.0-preview.1"
			cmd.Flags().String("project", "demo", "")
			cmd.Flags().String("output", "table", "")
			answer := "yes\nyes\n"
			if decline {
				answer = "no\n"
			}
			cmd.SetIn(strings.NewReader(answer))
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"localhost:8080"})
			err := cmd.Execute()
			want := []string{"/v1/health", "bootstrap", "ready", "/v1/status", "/v1/up", "/v1/services"}
			if decline {
				want = want[:2]
			}
			if (err != nil) != decline || !reflect.DeepEqual(steps, want) {
				t.Fatalf("steps=%v err=%v", steps, err)
			}
		})
	}
}

func TestServeBootstrapPropagatesDownloadFailure(t *testing.T) {
	interactiveFixture(t)
	oldTransport, oldEnsure := http.DefaultTransport, ensureUserDaemon
	t.Cleanup(func() { http.DefaultTransport, ensureUserDaemon = oldTransport, oldEnsure })
	http.DefaultTransport = bootstrapTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/health" {
			t.Fatalf("continued after bootstrap failure: %s", r.URL.Path)
		}
		return nil, syscall.ECONNREFUSED
	})
	want := errors.New("release archive checksum mismatch")
	ensureUserDaemon = func(context.Context, string, time.Duration, io.Writer, func(string) error) error { return want }
	cmd := newServe(&options{baseURL: "http://127.0.0.1:47780", timeout: time.Second})
	cmd.Flags().String("project", "demo", "")
	cmd.Flags().String("output", "table", "")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"localhost:8080"})
	if err := cmd.Execute(); !errors.Is(err, want) {
		t.Fatal(err)
	}
}
