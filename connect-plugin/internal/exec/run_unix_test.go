//go:build unix

package exec

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunWithSignalDeath(t *testing.T) {
	// A child that dies from a signal has no exit code; Run must map it to
	// 128+signal so RunWithOutput can os.Exit it verbatim (EXIT-01).
	fakeBin := buildFakeBinary(t, "testdata/fake-datum-connect")
	env := []string{"FAKE_DUMMY_MODE=self-kill"}

	result, err := Run(context.Background(), fakeBin, []string{"--json", "list"}, env, OutputModeJSON)
	if err != nil {
		t.Fatalf("Run() returned error (expected nil for signal death): %v", err)
	}
	want := 128 + int(syscall.SIGKILL)
	if result.ExitCode != want {
		t.Errorf("expected exit code %d for SIGKILL death, got %d", want, result.ExitCode)
	}
}

func TestRunForwardsSignalToChild(t *testing.T) {
	// Exercises the forwarding path: the child blocks in listen mode until it
	// receives SIGINT. Send SIGINT to ourselves; Forward must relay it to the
	// child, which then exits cleanly, and Run must return exactly once with
	// the child's real status rather than racing a second Wait.
	fakeBin := buildFakeBinary(t, "testdata/fake-datum-connect")
	env := []string{"DATUM_ACCESS_TOKEN=test-token"}

	type outcome struct {
		result *RunResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, err := Run(context.Background(), fakeBin, []string{"--json", "listen"}, env, OutputModeJSON)
		done <- outcome{r, err}
	}()

	// Give Run time to start the child and register its signal handler;
	// before that, SIGINT would terminate the test binary itself.
	time.Sleep(500 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("failed to send SIGINT to self: %v", err)
	}

	select {
	case o := <-done:
		if o.err != nil {
			t.Fatalf("Run() returned error: %v", o.err)
		}
		if o.result.ExitCode != 0 {
			t.Errorf("expected child to exit 0 after forwarded SIGINT, got %d", o.result.ExitCode)
		}
		if !strings.Contains(string(o.result.Stdout), "tunnel_ready") {
			t.Errorf("expected child to have emitted tunnel_ready before the signal, got: %s", o.result.Stdout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not return after forwarded SIGINT; signal was not relayed to the child")
	}
}
