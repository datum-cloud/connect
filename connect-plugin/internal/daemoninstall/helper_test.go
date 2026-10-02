//go:build darwin || linux

package daemoninstall

import (
	"context"
	"path/filepath"
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
