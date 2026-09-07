package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/creack/pty"
	"testing"
)

// TestInteractivePTY drives `tunnel interactive --dummy-origin` through a
// real pty end-to-end: the dashboard reaches ready, the dummy origin serves
// (and the dashboard observes) a request, and a 'q' keypress shuts the
// whole thing down cleanly — the same flow TestInteractiveRequiresTTY
// can't exercise, since it deliberately runs without a TTY.
func TestInteractivePTY(t *testing.T) {
	fakeBin := buildFakeDatumConnect(t)
	fakeHelper := buildFakeHelper(t, "testdata/fake-credentials-helper")
	pluginBin := buildPlugin(t)

	connectDir, _ := os.Getwd()
	addr := "localhost:0" // OS-assigned port — avoids colliding with other tests
	cmd := exec.Command(pluginBin, "tunnel", "interactive", "--dummy-origin", "--origin", addr)
	cmd.Env = append(os.Environ(),
		"FAKE_DATUM_CONNECT="+fakeBin,
		"DATUM_CREDENTIALS_HELPER="+fakeHelper,
		"DATUM_SESSION=dev",
		"DATUM_CONNECT_DIR="+connectDir,
		"PATH="+connectDir+":"+os.Getenv("PATH"),
		"COLUMNS=80", "LINES=24",
	)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatalf("pty.StartWithSize: %v", err)
	}
	defer ptmx.Close()

	screen, readErrCh := readPTYUntil(t, ptmx, "ready", 15*time.Second)
	if screen == nil {
		t.Fatal("dashboard never reached 'ready'")
	}

	// --origin localhost:0 means the OS picked the real port; the dashboard
	// renders it back as "dummy origin serving on http://...". Pull it out.
	addrRe := extractDummyOriginAddr(t, screen)

	resp, err := http.Get("http://" + addrRe + "/hello/world")
	if err != nil {
		t.Fatalf("GET dummy origin: %v", err)
	}
	var payload struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("dummy origin response is not valid JSON: %v", err)
	}
	resp.Body.Close()
	if payload.Method != "GET" || payload.Path != "/hello/world" {
		t.Errorf("unexpected dummy origin payload: %+v", payload)
	}

	// The dashboard should log the request it just observed.
	if screen, _ = readPTYUntil(t, ptmx, "GET /hello/world", 5*time.Second); screen == nil {
		t.Error("dashboard log should show the observed GET /hello/world request")
	}

	if _, err := ptmx.Write([]byte("q")); err != nil {
		t.Fatalf("write 'q' to pty: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Errorf("interactive should exit 0 after 'q', got: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("interactive did not exit within 10s of pressing 'q'")
		_ = cmd.Process.Kill()
	}
	<-readErrCh // drain the background reader goroutine
}

// readPTYUntil reads from ptmx until it sees needle or the timeout elapses.
// Returns the accumulated bytes read so far (nil on timeout/EOF-before-match)
// and a channel that closes once the background reader goroutine exits —
// callers should drain it before the test returns to avoid a goroutine leak
// warning.
func readPTYUntil(t *testing.T, ptmx *os.File, needle string, timeout time.Duration) ([]byte, chan struct{}) {
	t.Helper()
	type result struct {
		buf []byte
		ok  bool
	}
	resultCh := make(chan result, 1)
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		var buf bytes.Buffer
		chunk := make([]byte, 4096)
		for {
			n, err := ptmx.Read(chunk)
			if n > 0 {
				buf.Write(chunk[:n])
				if bytes.Contains(buf.Bytes(), []byte(needle)) {
					resultCh <- result{buf: append([]byte(nil), buf.Bytes()...), ok: true}
					return
				}
			}
			if err != nil {
				resultCh <- result{buf: nil, ok: false}
				return
			}
		}
	}()

	select {
	case res := <-resultCh:
		if res.ok {
			return res.buf, doneCh
		}
		return nil, doneCh
	case <-time.After(timeout):
		return nil, doneCh
	}
}

// extractDummyOriginAddr extracts the "host:port" the dashboard rendered
// for the dummy origin (from its "dummy origin serving on http://host:port"
// line), from the raw (ANSI-styled) pty screen bytes.
func extractDummyOriginAddr(t *testing.T, screen []byte) string {
	t.Helper()
	const marker = "dummy origin serving on http://"
	idx := bytes.Index(screen, []byte(marker))
	if idx < 0 {
		t.Fatalf("could not find dummy origin address in dashboard output:\n%s", screen)
	}
	rest := screen[idx+len(marker):]
	end := bytes.IndexAny(rest, "\x1b\r\n ")
	if end < 0 {
		end = len(rest)
	}
	addr := string(rest[:end])
	if addr == "" {
		t.Fatalf("empty dummy origin address parsed from dashboard output:\n%s", screen)
	}
	return addr
}
