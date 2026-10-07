//go:build darwin || linux

package daemoninstall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixtureArchive(t *testing.T, names ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		data := []byte("fixture daemon (never executed)")
		header := &tar.Header{Name: name, Size: int64(len(data)), Mode: 0755, Typeflag: tar.TypeReg}
		if name == "symlink" {
			header.Typeflag = tar.TypeSymlink
			header.Linkname = "/tmp/evil"
			header.Size = 0
			data = nil
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func fixtureInstaller(t *testing.T, archive []byte, badChecksum bool) (Installer, *int) {
	t.Helper()
	calls := 0
	hash := sha256.Sum256(archive)
	if badChecksum {
		hash[0] ^= 1
	}
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || !strings.HasPrefix(r.URL.String(), releases+"v1.0.0-preview.1/") {
			t.Fatalf("unpinned request %s", r.URL)
		}
		var body []byte
		switch path := filepath.Base(r.URL.Path); path {
		case "checksums.txt":
			body = []byte(fmt.Sprintf("%x  datumctl-connect_Darwin_arm64.tar.gz\n", hash))
		case "datumctl-connect_Darwin_arm64.tar.gz":
			body = archive
		default:
			t.Fatalf("unexpected artifact %s", path)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	return Installer{Root: filepath.Join(t.TempDir(), "runtime"), GOOS: "darwin", GOARCH: "arm64", Client: client}, &calls
}

func TestAcquirePinnedReleaseAndReuse(t *testing.T) {
	i, calls := fixtureInstaller(t, fixtureArchive(t, "README.md", binaryName), false)
	executable, err := i.Acquire(context.Background(), "v1.0.0-preview.1")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil || string(data) != "fixture daemon (never executed)" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	info, _ := os.Stat(executable)
	if info.Mode().Perm() != 0700 {
		t.Fatal(info.Mode())
	}
	again, err := i.Acquire(context.Background(), "v1.0.0-preview.1")
	if err != nil || again != executable || *calls != 2 {
		t.Fatalf("reuse %q %v calls=%d", again, err, *calls)
	}
	if err := os.WriteFile(executable, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Acquire(context.Background(), "v1.0.0-preview.1"); err == nil {
		t.Fatal("accepted corrupt installed binary")
	}
	if *calls != 2 {
		t.Fatal("tried overwriting corrupt installation")
	}
}

func TestAcquireFailsClosedAndCleansStage(t *testing.T) {
	for _, tt := range []struct {
		name              string
		entries           []string
		badHash, truncate bool
	}{
		{"checksum", []string{binaryName}, true, false},
		{"missing", []string{"README.md"}, false, false},
		{"duplicate", []string{binaryName, binaryName}, false, false},
		{"link", []string{binaryName, "symlink"}, false, false},
		{"traversal", []string{"../evil", binaryName}, false, false},
		{"parent", []string{"..", binaryName}, false, false},
		{"absolute", []string{"/evil", binaryName}, false, false},
		{"truncated", []string{binaryName}, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			archive := fixtureArchive(t, tt.entries...)
			if tt.truncate {
				archive = archive[:len(archive)-4]
			}
			i, _ := fixtureInstaller(t, archive, tt.badHash)
			if _, err := i.Acquire(context.Background(), "v1.0.0-preview.1"); err == nil {
				t.Fatal("accepted invalid archive")
			}
			entries, err := os.ReadDir(i.Root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("left staging or active files: %v %v", entries, err)
			}
		})
	}
}

func TestAcquireRejectsDevelopmentUnsupportedAndCancelled(t *testing.T) {
	i, calls := fixtureInstaller(t, nil, false)
	for _, version := range []string{"", "v0.1.0-dev", "v0.1.0+123456", "latest", "v1.0.0/evil"} {
		if _, err := i.Acquire(context.Background(), version); err == nil {
			t.Fatal(version)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := i.Acquire(ctx, "v1.0.0-preview.1"); err == nil {
		t.Fatal("ignored cancellation")
	}
	i.GOOS = "windows"
	if _, err := i.Acquire(context.Background(), "v1.0.0-preview.1"); err == nil {
		t.Fatal("accepted unsupported platform")
	}
	if *calls != 0 {
		t.Fatal("unexpected download")
	}
}

func TestDownloadErrorsAndLimits(t *testing.T) {
	for _, tt := range []struct {
		status int
		body   string
		limit  int64
		want   string
	}{
		{404, "", 10, "not published"}, {503, "secret", 10, "HTTP 503"}, {200, "too large", 3, "size limit"},
	} {
		c := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tt.status, Body: io.NopCloser(strings.NewReader(tt.body))}, nil
		})}
		err := download(context.Background(), c, releases+"v1.0.0/checksums.txt", io.Discard, tt.limit)
		if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "secret") {
			t.Fatal(err)
		}
	}
}

func TestRedirectAndChecksumTrust(t *testing.T) {
	for _, raw := range []string{"http://github.com/file", "https://evil.test/file", "https://github.com.evil.test/file", "https://user@github.com/file", "https://github.com:444/file"} {
		u, _ := url.Parse(raw)
		if trustedDownloadURL(u) {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{"https://github.com/file", "https://release-assets.githubusercontent.com/file"} {
		u, _ := url.Parse(raw)
		if !trustedDownloadURL(u) {
			t.Fatal(raw)
		}
	}
	hash := strings.Repeat("a", 64)
	for _, manifest := range []string{"", "bad  archive", hash + "  archive\n" + hash + "  archive"} {
		if _, err := checksumFor(manifest, "archive"); err == nil {
			t.Fatal(manifest)
		}
	}
	if got, err := checksumFor(hash+" *archive", "archive"); err != nil || got != hash {
		t.Fatal(got, err)
	}
}

func TestLockAndUnsafeRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	unlock, err := Lock(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(root); err == nil {
		t.Fatal("concurrent setup permitted")
	}
	unlock()
	unlock, err = Lock(root)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(root); err == nil {
		t.Fatal("accepted shared writable root")
	}
}

func TestAcquireRedirectCannotEscapeGitHub(t *testing.T) {
	i, _ := fixtureInstaller(t, nil, false)
	requests := 0
	i.Client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.Host != "github.com" {
			t.Fatal("contacted untrusted redirect host")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://attacker.invalid/secret?token=private"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	_, err := i.Acquire(context.Background(), "v1.0.0-preview.1")
	if err == nil || strings.Contains(err.Error(), "private") || requests != 1 {
		t.Fatalf("err=%v requests=%d", err, requests)
	}
}

func TestInstalledFileAndPathSafety(t *testing.T) {
	for _, kind := range []string{"shared", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			i, _ := fixtureInstaller(t, fixtureArchive(t, binaryName), false)
			executable, err := i.Acquire(context.Background(), "v1.0.0-preview.1")
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "shared":
				err = os.Chmod(executable, 0755)
			case "symlink":
				if err := os.Rename(executable, executable+".original"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(executable+".original", executable)
			case "hardlink":
				err = os.Link(executable, executable+".link")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := i.Acquire(context.Background(), "v1.0.0-preview.1"); err == nil {
				t.Fatal("accepted unsafe cached binary")
			}
		})
	}
}

func TestPlatformArtifactNames(t *testing.T) {
	for _, tt := range []struct{ goos, arch, want string }{
		{"darwin", "arm64", "Darwin_arm64"}, {"darwin", "amd64", "Darwin_x86_64"},
		{"linux", "arm64", "Linux_arm64"}, {"linux", "amd64", "Linux_x86_64"},
	} {
		got, err := assetName("v1.0.0", tt.goos, tt.arch)
		if err != nil || got != "datumctl-connect_"+tt.want+".tar.gz" {
			t.Fatal(got, err)
		}
	}
}
