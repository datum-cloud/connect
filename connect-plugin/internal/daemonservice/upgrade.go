package daemonservice

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"
	"go.datum.net/datumctl-plugins/connect/internal/daemoninstall"
	"go.datum.net/datumctl-plugins/connect/internal/state"
)

var launchdProgramArguments = regexp.MustCompile(`(?s)(<key>ProgramArguments</key>\s*<array>\s*<string>)(.*?)(</string>)`)

// skipAutomaticUpgrade leaves the running daemon alone for local builds, such
// as Taskfile's 0.1.0+<commit>, which have no release to download. An explicit
// executable or a forced upgrade still proceeds. version has no "v" prefix.
func skipAutomaticUpgrade(version, executable string, force bool) bool {
	return executable == "" && !force && !daemoninstall.PublishedRelease("v"+version)
}

// EnsureCurrentUser upgrades an installed standard user service when its
// daemon version differs from the plugin release. It does not install a
// missing service and it skips unpublished development plugin versions.
func EnsureCurrentUser(ctx context.Context, version, executable string, timeout time.Duration, progress io.Writer, force bool) (bool, bool, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return false, false, nil
	}
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if skipAutomaticUpgrade(version, executable, force) {
		return false, false, nil
	}
	if err := validatePlatformScope(false); err != nil {
		return false, false, err
	}
	root := filepath.Join(state.Dir(), "runtime")
	unlock, err := daemoninstall.Lock(root)
	if err != nil {
		return false, false, err
	}
	defer unlock()
	svc, _, err := makeService(false, "", 47780, "", "")
	if err != nil {
		return false, false, err
	}
	status, err := statusService(svc, false)
	if errors.Is(err, service.ErrNotInstalled) {
		return false, false, nil
	}
	if err != nil {
		return true, false, fmt.Errorf("check the existing Connect service before upgrading: %w", err)
	}
	if status != service.StatusRunning && status != service.StatusStopped {
		return true, false, fmt.Errorf("Connect user service has an unknown state; inspect `datumctl connect daemon status` before upgrading")
	}
	servicePath, err := userServiceConfigPath()
	if err != nil {
		return true, false, err
	}
	definition, err := os.ReadFile(servicePath)
	if err != nil {
		return true, false, fmt.Errorf("read the existing Connect service definition: %w", err)
	}
	oldExecutable, _, err := replaceServiceExecutable(runtime.GOOS, definition, "/datum-connectd")
	if err != nil {
		return true, false, fmt.Errorf("cannot safely inspect the existing Connect service: %w", err)
	}
	if executable != "" {
		if !filepath.IsAbs(executable) {
			return true, false, fmt.Errorf("--executable must be an absolute path")
		}
	} else if !force {
		currentVersion, versionErr := daemonExecutableVersion(oldExecutable)
		if versionErr == nil && currentVersion == version {
			return true, false, nil
		}
	}
	if executable == "" {
		executable, err = (daemoninstall.Installer{Root: root, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Progress: progress}).Acquire(ctx, "v"+version)
		if err != nil {
			return true, false, err
		}
	}
	if sameFilePath(oldExecutable, executable) {
		return true, false, nil
	}
	if err := upgradeUserService(ctx, svc, executable, timeout); err != nil {
		return true, false, err
	}
	return true, true, nil
}

// upgradeUserService swaps only the executable path in the existing user
// service definition. It preserves arguments, environment, restart policy,
// logs, and the service label while leaving all daemon state in place.
func upgradeUserService(ctx context.Context, svc service.Service, executable string, timeout time.Duration) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return fmt.Errorf("automatic daemon upgrades are supported on macOS and Linux user services only")
	}
	if !filepath.IsAbs(executable) {
		return fmt.Errorf("the replacement daemon path must be absolute")
	}
	if err := verifyDaemonExecutable(executable); err != nil {
		return fmt.Errorf("replacement daemon is not usable: %w", err)
	}
	status, err := statusService(svc, false)
	if err != nil {
		return fmt.Errorf("check the existing Connect service before upgrading: %w", err)
	}
	path, err := userServiceConfigPath()
	if err != nil {
		return err
	}
	oldConfig, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read the existing Connect service definition: %w", err)
	}
	oldExecutable, newConfig, err := replaceServiceExecutable(runtime.GOOS, oldConfig, executable)
	if err != nil {
		return fmt.Errorf("cannot safely upgrade the existing Connect service: %w", err)
	}
	if sameFilePath(oldExecutable, executable) {
		if status != service.StatusRunning {
			if err := svc.Start(); err != nil {
				return fmt.Errorf("start the existing Connect service: %w", err)
			}
		}
		return waitReady(ctx, "http://127.0.0.1:47780", timeout)
	}
	if status == service.StatusRunning {
		if err := runServiceAction(ctx, svc, func(s service.Service) error { return s.Stop() }, 30*time.Second); err != nil {
			return fmt.Errorf("stop the existing Connect service before upgrading: %w", err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect the existing Connect service definition: %w", err)
	}
	if !info.Mode().IsRegular() {
		if status == service.StatusRunning {
			_ = svc.Start()
		}
		return fmt.Errorf("the existing Connect service definition is not a regular file; left unchanged")
	}
	if err := atomicReplaceFile(path, newConfig, info.Mode().Perm()); err != nil {
		if status == service.StatusRunning {
			_ = svc.Start()
		}
		return fmt.Errorf("update the Connect service definition: %w", err)
	}
	if err := reloadUserServiceManager(); err != nil {
		return rollbackServiceUpgrade(path, oldConfig, info.Mode().Perm(), svc, status, fmt.Errorf("reload the service manager: %w", err))
	}
	if err := svc.Start(); err != nil {
		return rollbackServiceUpgrade(path, oldConfig, info.Mode().Perm(), svc, status, fmt.Errorf("start the upgraded Connect service: %w", err))
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if err := waitReady(ctx, "http://127.0.0.1:47780", timeout); err != nil {
		return rollbackServiceUpgrade(path, oldConfig, info.Mode().Perm(), svc, status, fmt.Errorf("the upgraded daemon did not become healthy: %w", err))
	}
	return nil
}

func rollbackServiceUpgrade(path string, previous []byte, mode os.FileMode, svc service.Service, previousStatus service.Status, cause error) error {
	var rollback []string
	if err := svc.Stop(); err != nil && previousStatus == service.StatusRunning {
		rollback = append(rollback, "stop replacement: "+err.Error())
	}
	if err := atomicReplaceFile(path, previous, mode); err != nil {
		rollback = append(rollback, "restore service definition: "+err.Error())
	} else if err := reloadUserServiceManager(); err != nil {
		rollback = append(rollback, "reload restored service definition: "+err.Error())
	}
	if previousStatus == service.StatusRunning {
		if err := svc.Start(); err != nil {
			rollback = append(rollback, "restart previous daemon: "+err.Error())
		}
	}
	if len(rollback) > 0 {
		return fmt.Errorf("%w; automatic rollback was incomplete (%s). Check `datumctl connect daemon status` and the daemon log", cause, strings.Join(rollback, "; "))
	}
	if previousStatus == service.StatusRunning {
		return fmt.Errorf("%w; restored the previous service definition and restarted the previous daemon", cause)
	}
	return fmt.Errorf("%w; restored the previous service definition and left the service stopped", cause)
}

func userServiceConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", serviceName+".plist"), nil
	case "linux":
		return filepath.Join(home, ".config", "systemd", "user", serviceName+".service"), nil
	default:
		return "", fmt.Errorf("automatic daemon upgrades are unsupported on %s", runtime.GOOS)
	}
}

func replaceServiceExecutable(goos string, content []byte, replacement string) (string, []byte, error) {
	switch goos {
	case "darwin":
		return replaceLaunchdExecutable(content, replacement)
	case "linux":
		return replaceSystemdExecutable(content, replacement)
	default:
		return "", nil, fmt.Errorf("unsupported service platform %s", goos)
	}
}

func replaceLaunchdExecutable(content []byte, replacement string) (string, []byte, error) {
	indices := launchdProgramArguments.FindSubmatchIndex(content)
	if len(indices) != 8 {
		return "", nil, fmt.Errorf("the service does not have a standard ProgramArguments entry")
	}
	encoded := content[indices[4]:indices[5]]
	var old string
	if err := xml.Unmarshal(append(append([]byte("<string>"), encoded...), []byte("</string>")...), &old); err != nil {
		return "", nil, fmt.Errorf("decode the service executable path: %w", err)
	}
	if !filepath.IsAbs(old) || (filepath.Base(old) != "datum-connect-daemon" && filepath.Base(old) != "datum-connectd") {
		return "", nil, fmt.Errorf("the service points to an unrecognized executable")
	}
	var escaped bytes.Buffer
	if err := xml.EscapeText(&escaped, []byte(replacement)); err != nil {
		return "", nil, err
	}
	updated := make([]byte, 0, len(content)+escaped.Len()-len(encoded))
	updated = append(updated, content[:indices[4]]...)
	updated = append(updated, escaped.Bytes()...)
	updated = append(updated, content[indices[5]:]...)
	return old, updated, nil
}

func replaceSystemdExecutable(content []byte, replacement string) (string, []byte, error) {
	lines := strings.SplitAfter(string(content), "\n")
	old := ""
	execStartCount := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "ExecStart=") {
			continue
		}
		execStartCount++
		command := strings.TrimPrefix(trimmed, "ExecStart=")
		end := strings.IndexAny(command, " \t\r\n")
		if end < 0 {
			end = len(command)
		}
		old = strings.ReplaceAll(command[:end], `\x20`, " ")
	}
	if execStartCount != 1 || !filepath.IsAbs(old) || (filepath.Base(old) != "datum-connect-daemon" && filepath.Base(old) != "datum-connectd") {
		return "", nil, fmt.Errorf("the service does not have one recognized ExecStart executable")
	}
	escapedOld := strings.ReplaceAll(old, " ", `\x20`)
	escapedNew := strings.ReplaceAll(replacement, " ", `\x20`)
	updated := strings.ReplaceAll(string(content), escapedOld, escapedNew)
	if updated == string(content) {
		return "", nil, fmt.Errorf("the executable path was not found in the service definition")
	}
	return old, []byte(updated), nil
}

func verifyDaemonExecutable(path string) error {
	_, err := daemonExecutableVersion(path)
	return err
}

func daemonExecutableVersion(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0) {
		return "", fmt.Errorf("%s is not a regular executable file", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("run %s --version: %w", path, err)
	}
	version := strings.TrimSpace(string(output))
	for _, prefix := range []string{"datum-connectd ", "datum-connect-daemon "} {
		if strings.HasPrefix(version, prefix) {
			return strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(version, prefix)), "v"), "V"), nil
		}
	}
	return "", fmt.Errorf("%s does not identify itself as a Datum Connect daemon", path)
}

func atomicReplaceFile(path string, content []byte, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refuse to replace non-regular service definition %s", path)
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".datum-connect-service-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func reloadUserServiceManager() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "--user", "daemon-reload").Run()
}

func sameFilePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}
