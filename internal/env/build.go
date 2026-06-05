// Package env provides functions to build the child process environment.
package env

import (
	"os"

	"go.datum.net/datumctl/plugin"
)

// Build returns the child process environment. Takes PluginContext and
// initial token. Returns a []string slice suitable for os/exec.Cmd.Env.
// Must include: DATUM_ACCESS_TOKEN, DATUM_API_HOST, DATUM_CONNECT_REPO,
// DATUM_CREDENTIALS_HELPER, DATUM_SESSION (plus inherited env).
func Build(ctx plugin.PluginContext, token string) []string {
	result := os.Environ()

	result = append(result, "DATUM_ACCESS_TOKEN="+token)
	result = append(result, "DATUM_API_HOST="+ctx.APIHost)
	result = append(result, "DATUM_CONNECT_REPO="+ctx.Project)
	result = append(result, "DATUM_CREDENTIALS_HELPER="+ctx.CredentialsHelper)
	result = append(result, "DATUM_SESSION="+ctx.Session)

	return result
}
