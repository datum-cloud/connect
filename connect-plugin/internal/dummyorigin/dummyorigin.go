// Package dummyorigin provides a minimal local HTTP server used as a
// stand-in local origin for `tunnel interactive --dummy-origin`, so there's
// something to tunnel to without standing up a real service first.
package dummyorigin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Server is a running dummy origin instance.
type Server struct {
	httpSrv *http.Server
	ln      net.Listener
}

type response struct {
	Message string    `json:"message"`
	Method  string    `json:"method"`
	Path    string    `json:"path"`
	Time    time.Time `json:"time"`
}

// Start binds addr (host:port) and begins serving in the background. It
// returns an error immediately if the address can't be bound (e.g. the port
// is already in use) — callers should surface this before spawning the
// tunnel binary against it.
//
// onRequest, if non-nil, is called synchronously for every request the
// server receives, before it responds — this is how a caller (e.g. the
// interactive dashboard) observes per-request traffic against the dummy
// origin, something not otherwise available until the Rust tunnel binary
// gains its own request-level instrumentation.
func Start(addr string, onRequest func(method, path string)) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dummy origin: bind %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if onRequest != nil {
			onRequest(r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response{
			Message: "hello from the datumctl connect dummy origin",
			Method:  r.Method,
			Path:    r.URL.Path,
			Time:    time.Now().UTC(),
		})
	})

	srv := &http.Server{Handler: mux}
	s := &Server{httpSrv: srv, ln: ln}
	go func() {
		// Serve returns http.ErrServerClosed after a clean Shutdown — expected,
		// not a runtime failure worth surfacing.
		_ = srv.Serve(ln)
	}()
	return s, nil
}

// Addr returns the bound address.
func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

// Shutdown gracefully stops the server, waiting for in-flight requests to
// finish or ctx to be done, whichever comes first.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}
