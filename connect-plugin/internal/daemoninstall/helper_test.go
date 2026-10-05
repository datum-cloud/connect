//go:build darwin || linux

package daemoninstall

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelperUsesExactReleaseAndSeparateVerifiedCache(t *testing.T) {
	i, calls := fixtureInstaller(t, fixtureArchive(t, binaryName, "datum-connect-network-helper"), false)
	daemon, err := i.Acquire(context.Background(), "v1.0.0-preview.1")
	if err != nil {
		t.Fatal(err)
	}
	helper, err := i.AcquireHelper(context.Background(), "v1.0.0-preview.1")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(daemon) == filepath.Dir(helper) || filepath.Base(helper) != "datum-connect-network-helper" {
		t.Fatal("mixed component caches")
	}
	if _, err = i.AcquireHelper(context.Background(), "v1.0.0-preview.1"); err != nil || *calls != 4 {
		t.Fatalf("cache not verified: calls=%d err=%v", *calls, err)
	}
	missing, _ := fixtureInstaller(t, fixtureArchive(t, binaryName), false)
	if _, err = missing.AcquireHelper(context.Background(), "v1.0.0-preview.1"); err == nil {
		t.Fatal("accepted archive without helper")
	}
	bad, _ := fixtureInstaller(t, fixtureArchive(t, "datum-connect-network-helper"), true)
	if _, err = bad.AcquireHelper(context.Background(), "v1.0.0-preview.1"); err == nil {
		t.Fatal("accepted bad archive checksum")
	}
}

func TestDevelopmentHelperErrorExplainsNextStep(t *testing.T) {
	i, calls := fixtureInstaller(t, nil, false)
	_, err := i.AcquireHelper(context.Background(), "v0.1.0-dev")
	if err == nil {
		t.Fatal("accepted development plugin version")
	}
	message := err.Error()
	for _, want := range []string{
		`plugin version "v0.1.0-dev"`,
		"not a published release",
		"Install a released Connect plugin",
		"datumctl connect join",
		"--helper-executable",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not explain %q", message, want)
		}
	}
	if strings.Contains(message, "connect install --executable") {
		t.Fatalf("helper error points to daemon installation: %q", message)
	}
	if *calls != 0 {
		t.Fatalf("unexpected download: %d requests", *calls)
	}
}
