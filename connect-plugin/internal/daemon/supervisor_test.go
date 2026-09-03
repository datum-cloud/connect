package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"go.datum.net/datumctl-plugins/connect/internal/pidfile"
)

func TestRunSupervisorStopsWhenContextExpires(t *testing.T) {
	fakeBin := findFakeBinary(t)
	setupFakeEnv(t, fakeBin)

	pidDir := t.TempDir()
	t.Setenv("DATUM_CONNECT_TUNNEL_DIR", pidDir)

	cfg := Config{
		Name:     "test-tun",
		Endpoint: "localhost:8080",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	err := RunSupervisor(ctx, cfg)
	if err == nil {
		t.Fatal("expected the context to terminate the child process")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("expected deadline expiry, got %v", ctx.Err())
	}
}

func TestRunSupervisorWritesAndRemovesPIDFile(t *testing.T) {
	fakeBin := findFakeBinary(t)
	setupFakeEnv(t, fakeBin)

	pidDir := t.TempDir()
	t.Setenv("DATUM_CONNECT_TUNNEL_DIR", pidDir)

	cfg := Config{
		Name:     "pidtest",
		Endpoint: "localhost:8080",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunSupervisor(ctx, cfg)
	}()

	pidPath := filepath.Join(pidDir, "pidtest.pid")
	deadline := time.Now().Add(2 * time.Second)
	var state *pidfile.PidFile
	for time.Now().Before(deadline) {
		var err error
		state, err = pidfile.Read(pidPath)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if state == nil {
		t.Fatal("supervisor did not write a readable PID file")
	}
	if state.GoPID != os.Getpid() || state.RustPID <= 0 || state.BinaryPath != fakeBin {
		t.Fatalf("unexpected PID file contents: %#v", state)
	}

	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected cancellation to terminate the child process")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not return after cancellation")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("PID file was not removed after supervisor exit: %v", err)
	}
}

func findFakeBinary(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test source")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	binName := "fake-datum-connect"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	bin := filepath.Join(t.TempDir(), binName)
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/fake-datum-connect")
	cmd.Dir = moduleRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake datum-connect: %v\n%s", err, out)
	}
	return bin
}

// setupFakeEnv sets up environment so binary.Discover() finds the fake binary
// and plugin.Token() finds a working fake credentials helper.
func setupFakeEnv(t *testing.T, fakeBin string) {
	t.Helper()
	t.Setenv("FAKE_DATUM_CONNECT", fakeBin)
	// Add fake binary dir to PATH
	fakeDir := filepath.Dir(fakeBin)
	t.Setenv("PATH", fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Build and use a fake credentials helper
	helperBin := buildFakeHelper(t)
	t.Setenv("DATUM_CREDENTIALS_HELPER", helperBin)

	// Set required datumctl env vars that plugin.Context() expects
	t.Setenv("DATUM_ORG", "test-org")
	t.Setenv("DATUM_PROJECT", "test-project")
	t.Setenv("DATUM_API_HOST", "api.datum.net")
	t.Setenv("DATUM_PLUGIN_API_VERSION", "1")
	t.Setenv("DATUM_SESSION", "dev")
}

// buildFakeHelper builds a simple credentials helper that returns a fixed token.
func buildFakeHelper(t *testing.T) string {
	t.Helper()
	helperDir := t.TempDir()
	src := `package main
import "fmt"
func main() { fmt.Println("test-token-from-helper") }
`
	srcPath := filepath.Join(helperDir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0644); err != nil {
		t.Fatalf("write helper source: %v", err)
	}
	binName := "fake-helper"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(helperDir, binName)
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	return binPath
}
