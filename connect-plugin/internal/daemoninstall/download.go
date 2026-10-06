// Package daemoninstall acquires a daemon from the CLI's exact GitHub release.
// It never executes downloaded code, enrolls devices, or manages OS services.
package daemoninstall

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	releases    = "https://github.com/datum-cloud/connect/releases/download/"
	maxArchive  = 160 << 20
	maxBinary   = 256 << 20
	maxExpanded = 512 << 20
	binaryName  = "datum-connectd"
)

var releaseTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)

type receipt struct {
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	ArchiveSHA256 string `json:"archive_sha256"`
	BinarySHA256  string `json:"binary_sha256"`
}

// Installer has injectable HTTP transport for offline fixture tests. The CLI
// does not expose arbitrary download URLs, tokens, or checksum bypasses.
type Installer struct {
	component    string
	Client       *http.Client
	Root         string
	GOOS, GOARCH string
	Progress     io.Writer
}

// AcquireHelper uses the same pinned release and archive checks as the daemon.
func (i Installer) AcquireHelper(ctx context.Context, version string) (string, error) {
	i.component = "datum-connect-network-helper"
	return i.Acquire(ctx, version)
}

func assetName(version, goos, arch string) (string, error) {
	if !releaseTag.MatchString(version) || strings.Contains(version, "dev") {
		return "", fmt.Errorf("plugin version %q is not a published release", version)
	}
	platform := map[string]string{"darwin": "Darwin", "linux": "Linux"}[goos]
	machine := map[string]string{"arm64": "arm64", "amd64": "x86_64"}[arch]
	if platform == "" || machine == "" {
		return "", fmt.Errorf("automatic daemon download is unsupported on %s/%s; use connect daemon install with an explicitly installed binary", goos, arch)
	}
	return "datumctl-connect_" + platform + "_" + machine + ".tar.gz", nil
}

// Acquire returns a private, immutable versioned executable. An existing
// installation must validate against its receipt; corruption never triggers
// an overwrite of a potentially running executable.
func (i Installer) Acquire(ctx context.Context, version string) (string, error) {
	executableName := binaryName
	if i.component != "" {
		executableName = i.component
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	asset, err := assetName(version, i.GOOS, i.GOARCH)
	if err != nil {
		if executableName == "datum-connect-network-helper" {
			return "", fmt.Errorf("cannot download a matching network helper: %w. Install a released Connect plugin to download its helper automatically, or rerun `datumctl connect join` with `--helper-executable /absolute/path/to/datum-connect-network-helper` to use a local helper", err)
		}
		return "", fmt.Errorf("cannot download the Connect daemon: %w. Install a released Connect plugin, or install a local daemon with `datumctl connect install --executable /absolute/path/to/datum-connectd`", err)
	}
	if i.Progress == nil {
		i.Progress = io.Discard
	}
	root, err := filepath.Abs(i.Root)
	if err != nil {
		return "", err
	}
	if err := privateDirectory(root); err != nil {
		return "", err
	}
	destination := filepath.Join(root, version+"-"+i.GOOS+"-"+i.GOARCH)
	if executableName != binaryName {
		destination += "-network-helper"
	}
	if _, err := os.Lstat(destination); err == nil {
		executable, err := verifyInstalledExecutable(destination, version, i.GOOS+"/"+i.GOARCH, executableName)
		if err == nil {
			fmt.Fprintf(i.Progress, "Using verified cached %s %s.\n", executableName, version)
		}
		return executable, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	client := i.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Minute}
	}
	// Copy, so the redirect policy cannot mutate the caller's client.
	copyClient := *client
	if copyClient.Timeout == 0 {
		copyClient.Timeout = 3 * time.Minute
	}
	copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many release redirects")
		}
		if !trustedDownloadURL(req.URL) {
			return fmt.Errorf("refuse release redirect outside GitHub HTTPS asset hosts")
		}
		return nil
	}
	base := releases + version + "/"
	fmt.Fprintf(i.Progress, "Downloading %s %s for %s/%s…\n", executableName, version, i.GOOS, i.GOARCH)
	var manifest strings.Builder
	if err := download(ctx, &copyClient, base+"checksums.txt", &manifest, 1<<20); err != nil {
		return "", err
	}
	want, err := checksumFor(manifest.String(), asset)
	if err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(root, ".download-")
	if err != nil {
		return "", err
	}
	// Only this call's private staging directory is removed on error.
	defer os.RemoveAll(stage)
	archivePath := filepath.Join(stage, "release.tar.gz")
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	hash := sha256.New()
	if err := download(ctx, &copyClient, base+asset, io.MultiWriter(archive, hash), maxArchive); err != nil {
		return "", err
	}
	if hex.EncodeToString(hash.Sum(nil)) != want {
		return "", fmt.Errorf("release archive checksum mismatch; no executable installed")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	binaryHash, err := extractExecutable(archive, filepath.Join(stage, executableName), executableName)
	if err != nil {
		return "", err
	}
	if err := archive.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(archivePath); err != nil {
		return "", err
	}
	r := receipt{Version: version, Platform: i.GOOS + "/" + i.GOARCH, ArchiveSHA256: want, BinarySHA256: binaryHash}
	encoded, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(stage, "receipt.json"), encoded, 0600); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := os.Rename(stage, destination); err != nil {
		// A concurrent installer may have completed the same immutable version.
		if existing, checkErr := verifyInstalledExecutable(destination, version, r.Platform, executableName); checkErr == nil {
			return existing, nil
		}
		return "", fmt.Errorf("activate downloaded daemon: %w", err)
	}
	fmt.Fprintf(i.Progress, "Verified release archive checksum and installed %s.\n", executableName)
	return filepath.Join(destination, executableName), nil
}

func trustedDownloadURL(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	switch u.Hostname() {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	default:
		return false
	}
}

func download(ctx context.Context, client *http.Client, source string, out io.Writer, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	if !trustedDownloadURL(req.URL) {
		return fmt.Errorf("refuse untrusted release URL")
	}
	req.Header.Set("User-Agent", "datum-connect-installer")
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("download %s: %w", path.Base(req.URL.Path), ctx.Err())
		}
		reason := "connection or release redirect failed"
		var dns *net.DNSError
		var netErr net.Error
		var certificate x509.CertificateInvalidError
		var unknownAuthority x509.UnknownAuthorityError
		switch {
		case errors.As(err, &dns):
			reason = "DNS lookup failed"
		case errors.As(err, &unknownAuthority), errors.As(err, &certificate):
			reason = "TLS certificate verification failed"
		case errors.As(err, &netErr) && netErr.Timeout():
			reason = "request timed out"
		}
		// Do not expose signed redirect URLs or proxy credentials in url.Error.
		return fmt.Errorf("download %s: %s; check connectivity and retry", path.Base(req.URL.Path), reason)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return fmt.Errorf("release artifact %s is not published for this plugin version; no fallback to latest", path.Base(req.URL.Path))
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", path.Base(req.URL.Path), res.StatusCode)
	}
	if res.ContentLength > limit {
		return fmt.Errorf("release artifact exceeds size limit")
	}
	n, err := io.Copy(out, io.LimitReader(res.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read release artifact: %w", err)
	}
	if n > limit {
		return fmt.Errorf("release artifact exceeds size limit")
	}
	return nil
}

func checksumFor(manifest, asset string) (string, error) {
	var result string
	for _, line := range strings.Split(manifest, "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || strings.TrimPrefix(parts[1], "*") != asset {
			continue
		}
		decoded, err := hex.DecodeString(parts[0])
		if err != nil || len(decoded) != sha256.Size || result != "" {
			return "", fmt.Errorf("invalid or duplicate release checksum for %s", asset)
		}
		result = strings.ToLower(parts[0])
	}
	if result == "" {
		return "", fmt.Errorf("release checksums do not include %s", asset)
	}
	return result, nil
}

func extractDaemon(archive io.Reader, destination string) (string, error) {
	return extractExecutable(archive, destination, binaryName)
}

func extractExecutable(archive io.Reader, destination, executableName string) (string, error) {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return "", fmt.Errorf("invalid release archive: %w", err)
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxExpanded + 1}
	tr := tar.NewReader(limited)
	var result string
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("invalid release archive: %w", err)
		}
		name := strings.TrimPrefix(header.Name, "./")
		if name == "" || name == ".." || path.IsAbs(name) || strings.Contains(name, "\\") || path.Clean(name) != strings.TrimSuffix(name, "/") || strings.HasPrefix(name, "../") {
			return "", fmt.Errorf("unsafe release archive path")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			return "", fmt.Errorf("release archive links and special files are forbidden")
		}
		if name != executableName {
			continue
		}
		if result != "" || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > maxBinary {
			return "", fmt.Errorf("invalid or duplicate daemon archive entry")
		}
		out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(io.MultiWriter(out, hash), tr)
		syncErr := out.Sync()
		modeErr := out.Chmod(0700)
		closeErr := out.Close()
		if err := errors.Join(copyErr, syncErr, modeErr, closeErr); err != nil {
			return "", err
		}
		result = hex.EncodeToString(hash.Sum(nil))
	}
	// Consume the gzip trailer to validate CRC and bound even trailing padding.
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return "", fmt.Errorf("invalid archive trailer: %w", err)
	}
	if limited.N <= 0 {
		return "", fmt.Errorf("expanded release archive exceeds size limit")
	}
	if result == "" {
		return "", fmt.Errorf("release archive does not contain %s", executableName)
	}
	return result, nil
}

func verifyInstalled(dir, version, platform string) (string, error) {
	return verifyInstalledExecutable(dir, version, platform, binaryName)
}

func verifyInstalledExecutable(dir, version, platform, executableName string) (string, error) {
	if err := checkPrivate(dir, true); err != nil {
		return "", err
	}
	metadata := filepath.Join(dir, "receipt.json")
	if err := checkPrivate(metadata, false); err != nil {
		return "", err
	}
	f, err := os.Open(metadata)
	if err != nil {
		return "", err
	}
	var r receipt
	err = json.NewDecoder(io.LimitReader(f, 4096)).Decode(&r)
	f.Close()
	if err != nil || r.Version != version || r.Platform != platform {
		return "", fmt.Errorf("invalid installed daemon receipt; installation left unchanged")
	}
	executable := filepath.Join(dir, executableName)
	if err := checkPrivate(executable, false); err != nil {
		return "", err
	}
	f, err = os.Open(executable)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0100 == 0 || info.Size() > maxBinary {
		return "", fmt.Errorf("invalid installed daemon permissions or size")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	if hex.EncodeToString(hash.Sum(nil)) != r.BinarySHA256 {
		return "", fmt.Errorf("installed daemon checksum mismatch; installation left unchanged")
	}
	return executable, nil
}

// privateDirectory refuses symlinks and shared writable ancestors. System-owned
// directory aliases (e.g. macOS /var) are resolved before creating private state.
func privateDirectory(dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse non-directory or symlink install path %s", dir)
		}
		return checkPrivate(dir, true)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return fmt.Errorf("invalid installation root")
	}
	if _, err := os.Stat(parent); errors.Is(err, os.ErrNotExist) {
		if err := privateDirectory(parent); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := checkParent(parent); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkPrivate(dir, true)
}
