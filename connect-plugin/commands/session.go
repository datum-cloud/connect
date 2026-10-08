package commands

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"go.datum.net/datumctl/plugin"
)

// datumctlSession contains host metadata, not an access or refresh token. The
// daemon pins this session and asks the host helper for access tokens as needed.
type datumctlSession struct {
	HelperPath  string `json:"helper_path"`
	Session     string `json:"session"`
	APIEndpoint string `json:"api_endpoint"`
	TokenURI    string `json:"token_uri,omitempty"`
}

func hostSession() (*datumctlSession, error) {
	ctx := plugin.Context()
	if strings.TrimSpace(ctx.Session) == "" || strings.TrimSpace(ctx.CredentialsHelper) == "" || strings.TrimSpace(ctx.APIHost) == "" {
		return nil, fmt.Errorf("no named datumctl session is available")
	}
	if !filepath.IsAbs(ctx.CredentialsHelper) {
		return nil, fmt.Errorf("datumctl helper must be an absolute path")
	}
	helper, err := filepath.Abs(ctx.CredentialsHelper)
	if err != nil {
		return nil, fmt.Errorf("resolve datumctl helper: %w", err)
	}
	helper, err = filepath.EvalSymlinks(helper)
	if err != nil {
		return nil, fmt.Errorf("resolve datumctl helper: %w", err)
	}
	info, err := os.Stat(helper)
	if err != nil {
		return nil, fmt.Errorf("inspect datumctl helper: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("datumctl helper must be a regular file")
	}
	endpoint := strings.TrimSpace(ctx.APIHost)
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("datumctl API host must be an origin without credentials, path, query, or fragment")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, fmt.Errorf("datumctl API host must use HTTPS (HTTP is allowed only on loopback for local testing)")
	}
	return &datumctlSession{HelperPath: helper, Session: ctx.Session, APIEndpoint: strings.TrimRight(endpoint, "/"), TokenURI: connectorTokenURI(u)}, nil
}

// connectorTokenURI is intentionally an allowlist, not hostname string
// rewriting. A service-account private key must never be sent to an endpoint
// inferred from an arbitrary custom API host.
func connectorTokenURI(api *url.URL) string {
	if api.Scheme != "https" {
		return ""
	}
	switch strings.ToLower(api.Hostname()) {
	case "api.datum.net":
		return "https://auth.datum.net/oauth/v2/token"
	case "api.staging.env.datum.net":
		return "https://auth.staging.env.datum.net/oauth/v2/token"
	default:
		return ""
	}
}

func addUpAuthentication(body map[string]any, auth, credentialsFile string) error {
	return addUpAuthenticationForPlatform(body, auth, credentialsFile, runtime.GOOS)
}

func addUpAuthenticationForPlatform(body map[string]any, auth, credentialsFile, goos string) error {
	switch auth {
	case "auto", "oidc", "stored":
	default:
		return fmt.Errorf("--auth must be auto, oidc, or stored")
	}
	if credentialsFile != "" && auth != "auto" {
		return fmt.Errorf("--auth %s cannot be combined with --credentials-file; omit --auth to import a credential file", auth)
	}
	body["auth"] = auth
	if credentialsFile != "" || auth == "stored" {
		return nil
	}
	if goos == "windows" {
		if auth == "oidc" {
			return fmt.Errorf("--auth oidc is unavailable with the local Windows system service because LocalSystem cannot use your interactive datumctl session; use --credentials-file with renewable Connector or service-account JSON, or --auth stored after file-credential setup")
		}
		// Auto may reuse credentials already stored by the service, but must not
		// send a host-session helper that LocalSystem cannot execute.
		return nil
	}
	session, err := hostSession()
	if err != nil {
		if auth == "oidc" {
			return fmt.Errorf("cannot use your datumctl session: %w. Run `datumctl login`, then `datumctl connect up --auth oidc` through datumctl", err)
		}
		// Ordinary up must resume saved credentials even if this invocation has
		// no usable host context. The daemon reports missing first-time auth.
		return nil
	}
	body["datumctl_session"] = session
	return nil
}
