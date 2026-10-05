package daemonservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"go.datum.net/datumctl-plugins/connect/internal/daemoninstall"
	"go.datum.net/datumctl-plugins/connect/internal/state"
)

type InterfaceApproval struct {
	InterfaceName   string   `json:"interface_name"`
	AssignedAddress string   `json:"assigned_address"`
	PeerAddress     string   `json:"peer_address"`
	MTU             uint16   `json:"mtu"`
	Routes          []string `json:"routes,omitempty"`
	AdvertiseRoutes []string `json:"advertise_routes,omitempty"`
}
type HelperApprovals struct {
	AllowedUID uint32              `json:"allowed_uid"`
	Approvals  []InterfaceApproval `json:"approvals"`
}

func sameApproval(a, b InterfaceApproval) bool {
	return a.InterfaceName == b.InterfaceName && a.AssignedAddress == b.AssignedAddress && a.PeerAddress == b.PeerAddress && a.MTU == b.MTU && slices.Equal(a.Routes, b.Routes) && slices.Equal(a.AdvertiseRoutes, b.AdvertiseRoutes)
}

type helperReceipt struct {
	Executable string `json:"executable"`
	SHA256     string `json:"sha256"`
}

// EnsureNetworking runs only after interactive consent. The daemon never elevates
// itself. Configuration crosses stdin; tokens and OIDC environment do not.
func EnsureNetworking(cmd *cobra.Command, version, executable string, config HelperApprovals, upgrade, replaceApproval bool) error {
	if runtime.GOOS == "windows" || os.Geteuid() <= 0 || config.AllowedUID != uint32(os.Geteuid()) {
		return fmt.Errorf("networking approval must run locally as the daemon's ordinary user")
	}
	if executable == "" {
		var err error
		executable, err = (daemoninstall.Installer{Root: filepath.Join(state.Dir(), "runtime"), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Progress: cmd.ErrOrStderr()}).AcquireHelper(cmd.Context(), version)
		if err != nil {
			return err
		}
	}
	executable, err := filepath.Abs(executable)
	if err != nil {
		return err
	}
	hash, err := executableHash(executable)
	if err != nil {
		return err
	}
	plugin, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	args := []string{"--", plugin, "daemon", "helper", "authorize", "--uid", strconv.FormatUint(uint64(config.AllowedUID), 10), "--executable", executable, "--sha256", hash}
	if upgrade {
		args = append(args, "--upgrade")
	}
	if replaceApproval {
		args = append(args, "--replace-approval")
	}
	child := exec.CommandContext(cmd.Context(), "/usr/bin/sudo", args...)
	// sudo reads the administrator password from /dev/tty, not plan stdin.
	child.Stdin, child.Stdout, child.Stderr = bytes.NewReader(data), cmd.ErrOrStderr(), cmd.ErrOrStderr()
	child.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if err := child.Run(); err != nil {
		return fmt.Errorf("networking approval did not complete; your user daemon and login are unchanged: %w", err)
	}
	return nil
}

func executableHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 256<<20 {
		return "", fmt.Errorf("invalid helper executable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, (256<<20)+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func mergeApprovals(existing, requested HelperApprovals, replace bool) (HelperApprovals, bool, error) {
	if requested.AllowedUID == 0 || requested.AllowedUID == ^uint32(0) || (existing.AllowedUID != 0 && existing.AllowedUID != requested.AllowedUID) {
		return HelperApprovals{}, false, fmt.Errorf("approval user mismatch")
	}
	merged := HelperApprovals{AllowedUID: requested.AllowedUID, Approvals: append([]InterfaceApproval(nil), existing.Approvals...)}
	changed := false
	for _, incoming := range requested.Approvals {
		found := false
		for i, current := range merged.Approvals {
			if current.InterfaceName == incoming.InterfaceName {
				if !sameApproval(current, incoming) {
					if !replace {
						return HelperApprovals{}, false, fmt.Errorf("existing administrator approval %q differs; review the displayed routes and retry with --replace-helper-approval", current.InterfaceName)
					}
					merged.Approvals[i] = incoming
					changed = true
				}
				found = true
			}
		}
		if !found {
			merged.Approvals = append(merged.Approvals, incoming)
		}
	}
	if len(merged.Approvals) == 0 || len(merged.Approvals) > 16 {
		return HelperApprovals{}, false, fmt.Errorf("approve between 1 and 16 peer host pairs")
	}
	return merged, changed, nil
}

// Hidden elevated implementation. Normal callers use join, not this command.
func helperAuthorizeCommand() *cobra.Command {
	var uid uint32
	var executable, digest string
	var upgrade, replaceApproval bool
	cmd := &cobra.Command{Use: "authorize", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
			return fmt.Errorf("unsupported helper platform")
		}
		if err := requireSystemPrivileges(); err != nil {
			return err
		}
		if uid == 0 || uid == ^uint32(0) {
			return fmt.Errorf("a non-root --uid is required")
		}
		if !filepath.IsAbs(executable) || len(digest) != 64 {
			return fmt.Errorf("absolute helper executable and SHA-256 required")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return err
		}
		var requested HelperApprovals
		decoder := json.NewDecoder(io.LimitReader(cmd.InOrStdin(), 65537))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&requested); err != nil {
			return err
		}
		if requested.AllowedUID != uid {
			return fmt.Errorf("approval allowed_uid differs from --uid")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return fmt.Errorf("unexpected data after approval document")
		}
		return authorizeNetworking(cmd.Context(), requested, executable, digest, upgrade, replaceApproval)
	}}
	cmd.Flags().Uint32Var(&uid, "uid", 0, "Approved user ID")
	cmd.Flags().StringVar(&executable, "executable", "", "Verified helper to stage")
	cmd.Flags().StringVar(&digest, "sha256", "", "Expected executable digest")
	cmd.Flags().BoolVar(&upgrade, "upgrade", false, "Approve restart to upgrade the helper; active IP attachments disconnect")
	cmd.Flags().BoolVar(&replaceApproval, "replace-approval", false, "Replace a changed administrator approval for the same interface")
	return cmd
}

func authorizeNetworking(ctx context.Context, requested HelperApprovals, source, digest string, upgrade, replaceApproval bool) error {
	dir := helperStateDir(requested.AllowedUID)
	if err := validatePrivilegedExecutable(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0711); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := validatePrivilegedExecutable(dir); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0711); err != nil {
		return err
	}
	// Serialize root-side configuration and service changes, separately from the
	// helper's socket lifetime lock. Never trust user-controlled install paths.
	unlock, err := daemoninstall.Lock(filepath.Join(dir, "installer"))
	if err != nil {
		return err
	}
	defer unlock()
	target := filepath.Join(dir, "helper-"+digest)
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		if err := copyPrivateFile(source, target, 256<<20); err != nil {
			return err
		}
		actual, err := executableHash(target)
		if err != nil {
			return err
		}
		if actual != digest {
			_ = os.Remove(target)
			return fmt.Errorf("helper changed after verification; no privileged code executed")
		}
		if err := os.Chmod(target, 0700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := validatePrivilegedExecutable(target); err != nil {
		return err
	}
	actual, err := executableHash(target)
	if err != nil || actual != digest {
		return fmt.Errorf("installed helper digest mismatch; left unchanged")
	}
	path := filepath.Join(dir, "approvals.json")
	var existing HelperApprovals
	var existingBytes []byte
	if data, err := os.ReadFile(path); err == nil {
		if err := validatePrivilegedExecutable(path); err != nil {
			return err
		}
		if err := json.Unmarshal(data, &existing); err != nil {
			return err
		}
		existingBytes = data
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	merged, approvalChanged, err := mergeApprovals(existing, requested, replaceApproval)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(merged)
	temporary, err := os.CreateTemp(dir, ".approval-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(check, target, "--config", name, "--check").CombinedOutput()
	if err != nil {
		return helperCheckError(output)
	}
	svc, err := service.New(nil, helperServiceConfig(requested.AllowedUID, target))
	if err != nil {
		return err
	}
	status, statusErr := svc.Status()
	var old helperReceipt
	receiptPath := filepath.Join(dir, "installed.json")
	if content, err := os.ReadFile(receiptPath); err == nil {
		if err := validatePrivilegedExecutable(receiptPath); err != nil {
			return err
		}
		if err := json.Unmarshal(content, &old); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	installed := statusErr == nil
	if statusErr != nil && !errors.Is(statusErr, service.ErrNotInstalled) {
		return statusErr
	}
	if installed && old.Executable == "" {
		return fmt.Errorf("existing helper is manually managed; automatic setup will not replace it")
	}
	if installed && old.Executable != target && !upgrade {
		return fmt.Errorf("helper upgrade requires explicit approval: retry join with --upgrade-helper; existing IP attachments will disconnect")
	}
	replacing := installed && old.Executable != target
	if approvalChanged && status == service.StatusRunning && !replacing {
		// A running helper keeps its startup configuration in memory. Restart it
		// only after explicit re-approval, and restore the previous file/service
		// if the new configuration cannot start.
		if err := svc.Stop(); err != nil {
			return fmt.Errorf("stop helper before replacing its approval: %w", err)
		}
		if err := os.Rename(name, path); err != nil {
			_ = svc.Start()
			return err
		}
		if err := svc.Start(); err != nil {
			restoreErr := writeRootFile(path, existingBytes)
			startErr := svc.Start()
			return errors.Join(fmt.Errorf("start helper with replacement approval: %w", err), restoreErr, startErr)
		}
		return nil
	}
	// Additive approvals preserve live sessions. A stopped or new service reads
	// the new file when it starts.
	receipt, _ := json.Marshal(helperReceipt{Executable: target, SHA256: digest})
	var restore func() error
	if replacing {
		if err := validatePrivilegedExecutable(old.Executable); err != nil {
			return err
		}
		previous, err := service.New(nil, helperServiceConfig(requested.AllowedUID, old.Executable))
		if err != nil {
			return err
		}
		restore = func() error {
			var failures []error
			if len(existingBytes) != 0 {
				if err := writeRootFile(path, existingBytes); err != nil {
					failures = append(failures, fmt.Errorf("restore previous helper approvals: %w", err))
				}
			}
			if err := previous.Install(); err != nil {
				failures = append(failures, fmt.Errorf("restore previous helper service: %w", err))
			} else {
				if status == service.StatusRunning {
					if err := previous.Start(); err != nil {
						failures = append(failures, fmt.Errorf("restart previous helper: %w", err))
					}
				}
				data, _ := json.Marshal(old)
				if err := writeRootFile(receiptPath, data); err != nil {
					failures = append(failures, fmt.Errorf("restore previous helper receipt: %w", err))
				}
			}
			return errors.Join(failures...)
		}
	} else if approvalChanged {
		restore = func() error {
			if len(existingBytes) == 0 {
				return nil
			}
			return writeRootFile(path, existingBytes)
		}
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return activateHelper(svc, installed, status, replacing, func() error { return writeRootFile(receiptPath, receipt) }, restore)
}

func helperCheckError(output []byte) error {
	message := strings.TrimSpace(string(output))
	if strings.Contains(message, "helper attachments must not install overlapping routes") {
		return fmt.Errorf("the selected networking helper is outdated and rejects overlapping route approvals saved for different networks. No approval or active interface was changed. Upgrade to a helper build that supports overlapping saved routes, then retry `datumctl connect join NETWORK --upgrade-helper --replace-helper-approval --helper-executable PATH`")
	}
	return fmt.Errorf("network helper rejected the requested approvals: %s", message)
}

func writeRootFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// Additive approvals do not restart a running helper. An explicitly approved
// binary replacement restores the previous service if activation fails.
func activateHelper(svc service.Service, installed bool, status service.Status, replacing bool, receipt func() error, restore func() error) error {
	rollback := func(cause error) error {
		if restore != nil {
			return errors.Join(cause, restore())
		}
		return cause
	}
	if replacing {
		if status == service.StatusRunning {
			if err := svc.Stop(); err != nil {
				return rollback(err)
			}
		}
		if err := svc.Uninstall(); err != nil {
			return rollback(err)
		}
		installed = false
	}
	added := false
	rollbackInstall := func(cause error) error {
		if added {
			_ = svc.Stop()
			if err := svc.Uninstall(); err != nil {
				cause = errors.Join(cause, fmt.Errorf("remove failed helper installation: %w", err))
			}
		}
		return rollback(cause)
	}
	if !installed {
		if err := svc.Install(); err != nil {
			return rollbackInstall(err)
		}
		added = true
	}
	if err := receipt(); err != nil {
		return rollbackInstall(err)
	}
	if !installed || status != service.StatusRunning {
		if err := svc.Start(); err != nil {
			return rollbackInstall(err)
		}
	}
	return nil
}
