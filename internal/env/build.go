// Package env provides functions to build the child process environment
// and to gate the plugin on required env-var contracts.
package env

import (
	"fmt"
	"io"
	"os"

	"go.datum.net/datumctl/plugin"
)

// Build returns the child process environment for the Rust binary.
//
// Phase 11.5: DATUM_CONNECT_DIR is OWNED by datumctl and arrives via
// os.Environ() pass-through; this function MUST NOT compute it, default
// it, or override it. The legacy DATUM_CONNECT_REPO=ctx.Project line is
// removed — it was the root cause of stray ./<project-slug>/ listen_key
// dirs (Phase 12 plan 12-02 scenario 6).
//
// Phase 13-06: DATUM_ACCESS_TOKEN line removed — the Rust binary now
// obtains its token from the credentials helper at startup. The helper
// receives DATUM_SESSION from the child env.
//
// Caller responsibility: check RequireConnectDir() before calling Build;
// if it returns an error, write FailConnectDirUnset() to stderr and
// os.Exit(64).
func Build(ctx plugin.PluginContext) []string {
	result := os.Environ()
	result = append(result, "DATUM_API_HOST="+ctx.APIHost)
	result = append(result, "DATUM_CREDENTIALS_HELPER="+ctx.CredentialsHelper)
	result = append(result, "DATUM_SESSION="+ctx.Session)
	return result
}

// RequireConnectDir returns nil when DATUM_CONNECT_DIR is set in the
// current process environment, and a sentinel error otherwise.
//
// Phase 11.5 D-11: single failure path; no distinction between
// "datumctl invoked me but forgot the var" and "user ran me directly".
func RequireConnectDir() error {
	if os.Getenv("DATUM_CONNECT_DIR") == "" {
		return fmt.Errorf("DATUM_CONNECT_DIR is not set in the environment")
	}
	return nil
}

// FailConnectDirUnset writes the multi-line directive error from
// CONTEXT.md D-09 to w. The caller is responsible for os.Exit(64).
func FailConnectDirUnset(w io.Writer) {
	const msg = `Error: DATUM_CONNECT_DIR is not set in the environment.

The connect plugin's state directory must be supplied by datumctl
when invoking the plugin. Normally this happens automatically when
you run:

  datumctl connect tunnel <subcommand> ...

If you are running the plugin binary directly for debugging, export
the canonical path manually:

  export DATUM_CONNECT_DIR="$HOME/.datumctl/connect"

(exit 64)
`
	fmt.Fprint(w, msg)
}
