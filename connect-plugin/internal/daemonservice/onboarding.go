package daemonservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
	"go.datum.net/datumctl-plugins/connect/internal/daemoninstall"
	"go.datum.net/datumctl-plugins/connect/internal/state"
)

// EnsureUser starts an existing user service or asks before installing one.
// It never replaces service configuration, installs a privileged service, or
// imports credentials. Callers must restrict this to interactive local setup.
func EnsureUser(ctx context.Context, version string, timeout time.Duration, progress io.Writer, confirm func(string) error) error {
	return bootstrapUser(ctx, version, "", timeout, progress, confirm, false)
}

func bootstrapUser(ctx context.Context, version, executable string, timeout time.Duration, progress io.Writer, confirm func(string) error, explicit bool) error {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return fmt.Errorf("guided setup requires an unprivileged macOS or Linux user; use explicit daemon service commands")
	}
	if err := validatePlatformScope(false); err != nil {
		return err
	}
	root := filepath.Join(state.Dir(), "runtime")
	unlock, err := daemoninstall.Lock(root)
	if err != nil {
		return err
	}
	defer unlock()
	svc, _, err := makeService(false, "", 47780, "", "")
	if err != nil {
		return err
	}
	if explicit {
		status, statusErr := svc.Status()
		if statusErr == nil {
			return fmt.Errorf("Connect user service is already installed (state %v); left unchanged. Use datumctl connect daemon status or datumctl connect daemon start", status)
		}
		if !errors.Is(statusErr, service.ErrNotInstalled) {
			return fmt.Errorf("check user daemon service: %w", statusErr)
		}
	}
	return ensureUserService(ctx, svc, progress, confirm, func() error {
		var err error
		if executable == "" {
			executable, err = (daemoninstall.Installer{Root: root, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Progress: progress}).Acquire(ctx, version)
			if err != nil {
				return err
			}
		}
		// Recheck after the download. Never replace a service installed meanwhile.
		if _, err := svc.Status(); !errors.Is(err, service.ErrNotInstalled) {
			return fmt.Errorf("service state changed during setup; left unchanged; inspect datumctl connect daemon status")
		}
		quiet := &cobra.Command{}
		quiet.SetContext(ctx)
		quiet.SetOut(io.Discard)
		quiet.SetErr(progress)
		if err := install(quiet, installOptions{port: 47780, executable: executable}); err != nil {
			return fmt.Errorf("register user daemon service: %w", err)
		}
		return nil
	}, func() error { return waitReady(ctx, connectapi.DefaultBaseURL, timeout) })
}

func ensureUserService(ctx context.Context, svc service.Service, progress io.Writer, confirm func(string) error, installService, ready func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status, err := svc.Status()
	switch {
	case errors.Is(err, service.ErrNotInstalled):
		if err := confirm("Download the matching Connect daemon and install a background service for your user? It will start at login."); err != nil {
			return err
		}
		if err := installService(); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("check user daemon service: %w", err)
	case status == service.StatusRunning:
		return fmt.Errorf("the user service is running but its API is unavailable; inspect datumctl connect daemon status and the daemon log (a custom API port requires --daemon-url)")
	case status != service.StatusStopped:
		return fmt.Errorf("the user service has an unknown state; inspect datumctl connect daemon status")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fmt.Fprintln(progress, "Starting Connect…")
	if err := svc.Start(); err != nil {
		return fmt.Errorf("start user daemon: %w", err)
	}
	if err := ready(); err != nil {
		return fmt.Errorf("Connect did not become ready: %w; inspect datumctl connect daemon status and %s", err, filepath.Join(serviceStateDir(false), "daemon.log"))
	}
	return nil
}
