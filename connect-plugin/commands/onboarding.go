package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
	"go.datum.net/datumctl-plugins/connect/internal/daemonservice"
	"go.datum.net/datumctl/plugin"
	"golang.org/x/term"
)

var interactiveTerminal = func(cmd *cobra.Command) bool {
	f, ok := cmd.InOrStdin().(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
var ensureUserDaemon = daemonservice.EnsureUser
var guidedSetupEnabled = guidedSetup

func guidedSetup(cmd *cobra.Command, opts *options) bool {
	format, _ := cmd.Flags().GetString("output")
	return interactiveTerminal(cmd) && (format == "" || format == "table") &&
		runtime.GOOS != "windows" && os.Geteuid() != 0 &&
		opts.baseURL == connectapi.DefaultBaseURL && opts.tokenFile == "" &&
		strings.TrimSpace(os.Getenv("DATUM_CONNECT_TOKEN")) == ""
}

func confirmSetup(cmd *cobra.Command, question string) error {
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", question)
	// Read a line without buffering ahead of datumctl's subsequent picker.
	var line strings.Builder
	for line.Len() < 256 {
		var input [1]byte
		_, err := io.ReadFull(cmd.InOrStdin(), input[:])
		if err != nil {
			return fmt.Errorf("setup cancelled")
		}
		b := input[0]
		if b == '\n' {
			break
		}
		line.WriteByte(b)
	}
	if answer := strings.ToLower(strings.TrimSpace(line.String())); answer != "y" && answer != "yes" {
		return fmt.Errorf("setup cancelled; no further changes made")
	}
	return nil
}

func ensureDaemonForUp(cmd *cobra.Command, opts *options) error {
	if !guidedSetupEnabled(cmd, opts) {
		return nil
	}
	client, err := connectapi.New(opts.baseURL, "", min(opts.timeout, 2*time.Second))
	if err != nil {
		return err
	}
	if opts.verbose {
		client.SetDiagnostics(cmd.ErrOrStderr())
	}
	_, err = client.Request(cmd.Context(), http.MethodGet, "/v1/health", "", nil)
	if err == nil {
		return nil
	}
	// A timeout or unexpected HTTP response is not permission to take over a
	// listener or change an existing service. Only connection refusal qualifies.
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return friendlyError(cmd, opts, "", err)
	}
	return ensureUserDaemon(cmd.Context(), cmd.Root().Version, opts.timeout, cmd.ErrOrStderr(), func(question string) error { return confirmSetup(cmd, question) })
}

// Host context is an environment snapshot. After login/context selection, ask
// datumctl to dispatch us again so the SDK receives the refreshed context.
func hostSetup(cmd *cobra.Command, login bool) error {
	stage, args := "context", []string{"ctx", "use"}
	question := "Choose a project using datumctl's context picker?"
	if login {
		stage, args = "login", []string{"login"}
		question = "Sign in using datumctl login?"
		api := strings.TrimPrefix(strings.TrimRight(plugin.Context().APIHost, "/"), "https://")
		if api != "" && api != "api.datum.net" {
			return fmt.Errorf("sign in to your chosen environment with datumctl login, then rerun connect up; guided login will not switch %q to the default environment", api)
		}
	}
	marker := "DATUM_CONNECT_GUIDED_" + strings.ToUpper(stage)
	if os.Getenv(marker) == "1" {
		return fmt.Errorf("datumctl %s did not provide a usable project/login context; select a project with datumctl ctx use, then retry connect up", strings.Join(args, " "))
	}
	helper := plugin.Context().CredentialsHelper
	if !filepath.IsAbs(helper) {
		return fmt.Errorf("run connect up through datumctl so guided setup can use its login and context picker")
	}
	helper, err := filepath.EvalSymlinks(helper)
	if err != nil {
		return fmt.Errorf("resolve datumctl executable: %w", err)
	}
	info, err := os.Stat(helper)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("datumctl executable is unavailable")
	}
	if err := confirmSetup(cmd, question); err != nil {
		return err
	}
	env := hostEnvironment(os.Environ())
	child := exec.CommandContext(cmd.Context(), helper, args...)
	child.Env, child.Stdin, child.Stdout, child.Stderr = env, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := child.Run(); err != nil {
		return fmt.Errorf("datumctl %s failed: %w", strings.Join(args, " "), err)
	}
	retry := []string{"connect", cmd.Name()}
	retry = append(retry, cmd.Flags().Args()...)
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		value := flag.Value.String()
		if list, ok := flag.Value.(pflag.SliceValue); ok {
			value = strings.Join(list.GetSlice(), ",")
		}
		retry = append(retry, "--"+flag.Name+"="+value)
	})
	child = exec.CommandContext(cmd.Context(), helper, retry...)
	child.Env = append(env, marker+"=1")
	child.Stdin, child.Stdout, child.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := child.Run(); err != nil {
		return fmt.Errorf("connect %s after %s: %w", cmd.Name(), stage, err)
	}
	return nil
}

// prepareServe enrolls only for an interactive local human. Scripts and scoped
// API clients retain the explicit up requirement and never inherit setup rights.
// handled means a host login/context picker redispatched the whole command.
func prepareServe(cmd *cobra.Command, opts *options) (handled bool, err error) {
	if !guidedSetupEnabled(cmd, opts) {
		return false, nil
	}
	p, err := project(cmd)
	if err != nil {
		return true, hostSetup(cmd, strings.TrimSpace(os.Getenv("DATUM_SESSION")) == "")
	}
	if err := ensureDaemonForUp(cmd, opts); err != nil {
		return false, err
	}
	client, err := opts.client(cmd, true)
	if err != nil {
		return false, err
	}
	result, err := client.Request(cmd.Context(), http.MethodGet, "/v1/status", p, nil)
	if err != nil {
		return false, friendlyError(cmd, opts, p, err)
	}
	var status struct {
		Running              bool   `json:"running"`
		DesiredUp            bool   `json:"desired_up"`
		Enrolled             bool   `json:"enrolled"`
		CredentialConfigured bool   `json:"credential_configured"`
		LastError            string `json:"last_error"`
	}
	if err := json.Unmarshal(result, &status); err != nil {
		return false, err
	}
	if status.Running {
		return false, nil
	}
	if status.Enrolled && !status.DesiredUp {
		if err := confirmSetup(cmd, "Connect is down. Reconnect and restore this project's saved services and forwards?"); err != nil {
			return false, err
		}
	} else if status.Enrolled && status.LastError != "" {
		return false, fmt.Errorf("Connect needs attention: %s\nRun datumctl connect up to reconnect explicitly", status.LastError)
	}
	if !status.CredentialConfigured {
		if _, err := hostSession(); err != nil {
			return true, hostSetup(cmd, true)
		}
		if err := confirmSetup(cmd, fmt.Sprintf("Connect this device to project %q using your current datumctl session?", p)); err != nil {
			return false, err
		}
	}
	body := map[string]any{"project": p, "name_hint": deviceNameHint()}
	if err := addUpAuthentication(body, "auto", ""); err != nil {
		return false, err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Connecting to project %q…\n", p)
	_, err = client.Request(cmd.Context(), http.MethodPost, "/v1/up", "", body)
	if err != nil {
		return false, friendlyError(cmd, opts, p, err)
	}
	return false, nil
}

func hostEnvironment(env []string) []string {
	var result []string
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "DATUM_PROJECT", "DATUM_ORG", "DATUM_API_HOST", "DATUM_PLUGIN_API_VERSION", "DATUM_CREDENTIALS_HELPER", "DATUM_SESSION":
			continue
		}
		result = append(result, entry)
	}
	return result
}

func deviceNameHint() string {
	hostname, _ := os.Hostname()
	hostname = strings.TrimSuffix(strings.ToLower(hostname), ".local")
	var value strings.Builder
	for _, c := range hostname {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			value.WriteRune(c)
		} else {
			value.WriteByte('-')
		}
	}
	name := strings.Trim(value.String(), "-")
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	if name == "" {
		return "device"
	}
	return name
}

func validDeviceName(name string) bool {
	if len(name) == 0 || len(name) > 63 || strings.Trim(name, "-") != name {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
