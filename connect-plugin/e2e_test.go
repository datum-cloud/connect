package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var testPlugin string

func TestMain(m *testing.M) {
	// Cross-compiled tests can exercise the actual packaged executable without
	// requiring a second Go toolchain inside the target OS or Wine environment.
	// Normal go test continues to build a fresh plugin from this checkout.
	if prebuilt := os.Getenv("DATUM_CONNECT_TEST_PLUGIN"); prebuilt != "" {
		info, err := os.Stat(prebuilt)
		if !filepath.IsAbs(prebuilt) || err != nil || !info.Mode().IsRegular() {
			fmt.Fprintln(os.Stderr, "DATUM_CONNECT_TEST_PLUGIN must name an existing absolute executable path")
			os.Exit(1)
		}
		testPlugin = prebuilt
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "connect-cli-tests-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	testPlugin = filepath.Join(dir, "datumctl-connect")
	if runtime.GOOS == "windows" {
		testPlugin += ".exe"
	}
	build := exec.Command("go", "build", "-o", testPlugin, ".")
	if output, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build plugin: %v\n%s", err, output)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	result := m.Run()
	os.RemoveAll(dir)
	os.Exit(result)
}

func buildPlugin(t *testing.T) string { t.Helper(); return testPlugin }

func TestPluginManifestBeforeCommandParsing(t *testing.T) {
	out, err := exec.Command(testPlugin, "--plugin-manifest", "--unknown-flag").CombinedOutput()
	if err != nil {
		t.Fatalf("manifest: %v\n%s", err, out)
	}
	var manifest map[string]any
	if err := json.Unmarshal(out, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["name"] != "connect" || manifest["api_version"] != float64(1) {
		t.Fatalf("unexpected manifest: %s", out)
	}
}

func TestFlatCommandSurface(t *testing.T) {
	out, err := exec.Command(testPlugin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("help: %v\n%s", err, out)
	}
	available := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && strings.HasPrefix(line, "  ") {
			available[fields[0]] = true
		}
	}
	for _, name := range []string{"up", "down", "status", "serve", "unserve", "dial", "hangup", "join", "leave", "ping", "daemon", "install", "health", "version"} {
		if !available[name] {
			t.Errorf("missing flat command %q", name)
		}
		if output, err := exec.Command(testPlugin, name, "--help").CombinedOutput(); err != nil {
			t.Errorf("%s help: %v\n%s", name, err, output)
		}
	}
	for _, name := range []string{"tunnel", "login", "project", "network", "peer", "list", "update", "delete", "ps", "logs", "stop"} {
		if available[name] {
			t.Errorf("legacy command %q remains", name)
		}
	}
}

func TestRemovedCommandsFailWithoutSideEffects(t *testing.T) {
	for _, args := range [][]string{{"tunnel"}, {"tunnel", "listen", "--endpoint", "localhost:8080"}, {"login"}, {"project", "join"}, {"network"}, {"peer"}} {
		t.Run(strings.Join(args, "-"), func(t *testing.T) {
			command := exec.Command(testPlugin, args...)
			stateDir := t.TempDir()
			command.Env = append(os.Environ(), "DATUM_CONNECT_DIR="+stateDir)
			out, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("removed command succeeds: %s", out)
			}
			if !strings.Contains(string(out), "unknown command") && !strings.Contains(string(out), "unknown flag") {
				t.Fatalf("expected a parse error, got: %s", out)
			}
			entries, err := os.ReadDir(stateDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("removed command touched state: %v %v", entries, err)
			}
		})
	}
}

func TestNoArgumentsShowHelp(t *testing.T) {
	out, err := exec.Command(testPlugin).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Services are private") {
		t.Fatalf("root help: %v\n%s", err, out)
	}
}

func TestRootHelpIsPlatformSpecific(t *testing.T) {
	windowsLong, windowsExample := rootHelp("windows", `C:\ProgramData\Datum\Connect\daemon_auth\setup.token`)
	for _, want := range []string{"LocalSystem", "service-account", "--system", "--credentials-file", "--token-file", `C:\ProgramData\Datum\Connect`} {
		if !strings.Contains(windowsLong+windowsExample, want) {
			t.Errorf("Windows help lacks %q", want)
		}
	}
	unixLong, unixExample := rootHelp("linux", "/unused")
	if !strings.Contains(unixLong+unixExample, "datumctl login") || strings.Contains(unixLong+unixExample, "LocalSystem") {
		t.Fatalf("unexpected Unix help: %s\n%s", unixLong, unixExample)
	}
}
