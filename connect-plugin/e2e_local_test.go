package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestLocalShareAndTicketDial runs `connect local` and `connect dial TICKET`
// as real processes against a real datum-connectd, with no datumctl session
// and relays disabled, and fetches an HTTP response through the share.
//
// Set DATUM_CONNECTD to an absolute datum-connectd path to run it:
//
//	DATUM_CONNECTD=$PWD/../connect-lib/target/debug/datum-connectd go test -run TestLocalShareAndTicketDial .
func TestLocalShareAndTicketDial(t *testing.T) {
	daemon := os.Getenv("DATUM_CONNECTD")
	if daemon == "" {
		t.Skip("set DATUM_CONNECTD to a datum-connectd binary to run")
	}
	if runtime.GOOS == "windows" {
		t.Skip("uses SIGINT to stop foreground commands")
	}
	if !filepath.IsAbs(daemon) {
		t.Fatalf("DATUM_CONNECTD must be absolute: %s", daemon)
	}

	origin := httpOrigin(t, "hello through connect local")

	// The plugin finds datum-connectd in PATH. Strip any datumctl session so
	// the test proves no login is involved.
	bin := t.TempDir()
	if err := os.Symlink(daemon, filepath.Join(bin, "datum-connectd")); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + t.TempDir(), "DATUM_CONNECT_RELAY_URLS=none"}

	share := startForeground(t, env, "local", origin, "--max-peers", "1", "--name", "E2E service", "-o", "json")
	ready := share.next(t, "share_ready")
	ticket, _ := ready["ticket"].(string)
	if !strings.HasPrefix(ticket, "DCSHARE2") {
		t.Fatalf("share_ready ticket = %q", ticket)
	}

	dial := startForeground(t, env, "dial", ticket, "-o", "json")
	dialReady := dial.next(t, "dial_ready")
	local, _ := dialReady["local_addr"].(string)
	if dialReady["sharer_name"] != "E2E service" {
		t.Fatalf("dial_ready sharer_name = %v", dialReady["sharer_name"])
	}
	if paired := share.next(t, "share_paired"); paired["peer"] == "" {
		t.Fatalf("share_paired without peer: %v", paired)
	}

	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://" + local + "/")
	if err != nil {
		t.Fatalf("GET through share: %v\ndial stderr: %s", err, dial.stderr.String())
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello through connect local" {
		t.Fatalf("body = %q", body)
	}

	// Both ends report the path once traffic flows; with relays disabled it
	// can only be direct.
	if path := dial.next(t, "dial_path"); path["path"] != "direct" {
		t.Fatalf("dial_path = %v", path)
	}
	if path := share.next(t, "share_path"); path["path"] != "direct" {
		t.Fatalf("share_path = %v", path)
	}

	// A second device is refused once the peer limit is reached.
	second := exec.Command(testPlugin, "dial", ticket, "-o", "json")
	second.Env = env
	out, err := second.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "pairing limit reached") {
		t.Fatalf("second dial: err=%v output=%s", err, out)
	}

	dial.interrupt(t)
	share.interrupt(t)
}

func httpOrigin(t *testing.T, body string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, body)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return listener.Addr().String()
}

type foreground struct {
	cmd    *exec.Cmd
	events chan map[string]any
	stderr *strings.Builder
}

// startForeground runs the plugin and decodes its JSON event lines.
func startForeground(t *testing.T, env []string, args ...string) *foreground {
	t.Helper()
	cmd := exec.Command(testPlugin, args...)
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f := &foreground{cmd: cmd, events: make(chan map[string]any, 8), stderr: stderr}
	go func() {
		defer close(f.events)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var event map[string]any
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				f.events <- event
			}
		}
	}()
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return f
}

func (f *foreground) next(t *testing.T, name string) map[string]any {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		select {
		case event, ok := <-f.events:
			if !ok {
				t.Fatalf("%s exited before %s: %v\nstderr: %s", f.cmd.Args[1], name, f.cmd.Wait(), f.stderr.String())
			}
			if event["event"] == name {
				return event
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %s\nstderr: %s", name, f.stderr.String())
		}
	}
}

// interrupt sends Ctrl+C and expects a clean, prompt exit.
func (f *foreground) interrupt(t *testing.T) {
	t.Helper()
	if err := f.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s after Ctrl+C: %v\nstderr: %s", f.cmd.Args[1], err, f.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal(fmt.Sprintf("%s did not exit after Ctrl+C", f.cmd.Args[1]))
	}
}
