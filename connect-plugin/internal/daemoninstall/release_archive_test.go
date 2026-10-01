//go:build darwin || linux

package daemoninstall

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Optional real-bundle smoke test: run the production acquisition/extraction
// code against a locally packaged release through a fake HTTP transport.
// It never binds a socket, downloads from GitHub, or executes the daemon.
func TestReleaseArchiveInstallContract(t *testing.T) {
	archivePath := os.Getenv("DATUM_CONNECT_TEST_ARCHIVE")
	if archivePath == "" {
		t.Skip("set DATUM_CONNECT_TEST_ARCHIVE to a native preview archive")
	}
	version := os.Getenv("DATUM_CONNECT_TEST_RELEASE")
	asset, err := assetName(version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(archivePath) != asset {
		t.Fatalf("unexpected archive name: %s", archivePath)
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(archivePath), "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		var body []byte
		switch r.URL.String() {
		case releases + version + "/checksums.txt":
			body = manifest
		case releases + version + "/" + asset:
			body = archive
		default:
			t.Fatalf("unexpected request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	i := Installer{Client: client, Root: filepath.Join(t.TempDir(), "runtime"), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	executable, err := i.Acquire(context.Background(), version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(executable); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Acquire(context.Background(), version); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("expected two requests and cached reuse, got %d", requests)
	}
}
