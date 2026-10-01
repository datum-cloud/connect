// Package commands contains the daemon-backed Datum Connect CLI commands.
package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
	"go.datum.net/datumctl-plugins/connect/internal/daemonservice"
	"go.datum.net/datumctl-plugins/connect/internal/output"
	"go.datum.net/datumctl-plugins/connect/internal/state"
)

type options struct {
	baseURL   string
	tokenFile string
	timeout   time.Duration
	verbose   bool
}

// Add installs the daemon-backed commands on the plugin root.
func Add(root *cobra.Command) {
	opts := &options{}
	previousPreRun := root.PersistentPreRunE
	previousPreRunPlain := root.PersistentPreRun
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("output")
		if format != "table" && format != "json" && format != "yaml" {
			return fmt.Errorf("unsupported output format %q (use table, json, or yaml)", format)
		}
		if previousPreRun != nil {
			return previousPreRun(cmd, args)
		}
		if previousPreRunPlain != nil {
			previousPreRunPlain(cmd, args)
		}
		return nil
	}
	root.PersistentFlags().StringVar(&opts.baseURL, "daemon-url", connectapi.DefaultBaseURL, "Datum Connect daemon URL")
	root.PersistentFlags().StringVar(&opts.tokenFile, "token-file", "", "File containing a daemon bearer token")
	root.PersistentFlags().DurationVar(&opts.timeout, "timeout", 30*time.Second, "Daemon request timeout")
	root.PersistentFlags().BoolVarP(&opts.verbose, "verbose", "v", false, "Print request timing and connectivity diagnostics (never tokens or bodies)")

	root.AddCommand(newHealth(opts))
	root.AddCommand(newStatus(opts))
	root.AddCommand(newUp(opts))
	root.AddCommand(newDown(opts))
	root.AddCommand(newServe(opts))
	root.AddCommand(newUnserve(opts))
	root.AddCommand(newDial(opts))
	root.AddCommand(newHangup(opts))
	root.AddCommand(newJoin(opts))
	root.AddCommand(newLeave(opts))
	root.AddCommand(newPing(opts))
	root.AddCommand(newDaemon())
	root.AddCommand(daemonservice.BootstrapCommand())
}

func project(cmd *cobra.Command) (string, error) {
	p, err := cmd.Flags().GetString("project")
	if err != nil {
		return "", err
	}
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("choose a project with --project PROJECT or your datumctl context.\nExample: datumctl connect %s --project PROJECT", cmd.Name())
	}
	return p, nil
}

func (o *options) client(cmd *cobra.Command, auth bool) (*connectapi.Client, error) {
	token := ""
	if auth {
		var err error
		token, err = resolveToken(cmd, o.tokenFile)
		if err != nil {
			return nil, err
		}
	}
	client, err := connectapi.New(o.baseURL, token, o.timeout)
	if err == nil && o.verbose {
		client.SetDiagnostics(cmd.ErrOrStderr())
	}
	return client, err
}

func resolveToken(cmd *cobra.Command, explicit string) (string, error) {
	if explicit != "" {
		return readToken(explicit)
	}
	if token := strings.TrimSpace(os.Getenv("DATUM_CONNECT_TOKEN")); token != "" {
		return token, nil
	}
	// The setup token is a privileged local credential. Only an interactive
	// terminal gets the convenience fallback; automation must explicitly pass
	// --token-file or DATUM_CONNECT_TOKEN.
	if interactiveTerminal(cmd) {
		tokenPath := state.SetupTokenPath()
		if runtime.GOOS == "windows" {
			tokenPath = daemonservice.SystemSetupTokenPath()
		}
		token, err := readToken(tokenPath)
		if err != nil && errors.Is(err, os.ErrNotExist) {
			if runtime.GOOS == "windows" {
				return "", fmt.Errorf("local Connect daemon setup is unavailable.\nFrom elevated PowerShell, install and start with --system and --credentials-file.\nThen pass --token-file %q", daemonservice.SystemSetupTokenPath())
			}
			return "", fmt.Errorf("local Connect daemon setup is unavailable.\nIf not installed: datumctl connect daemon install\nThen run: datumctl connect daemon start")
		}
		return token, err
	}
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("local daemon authentication required.\nRun from an elevated terminal and pass --token-file %q, or set DATUM_CONNECT_TOKEN to a scoped token.\nThis authorizes access to the local daemon, not your Datum cloud account", daemonservice.SystemSetupTokenPath())
	}
	return "", fmt.Errorf("local daemon authentication required for automation.\nSupply a scoped daemon token with --token-file PATH or DATUM_CONNECT_TOKEN.\nThis authorizes access to the local daemon, not your Datum cloud account.\nThe privileged setup token is loaded automatically only in an interactive terminal")
}

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read daemon token %s: %w", path, err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("daemon token file %s is empty", path)
	}
	return token, nil
}

func runRequest(cmd *cobra.Command, opts *options, auth bool, method, path, projectID string, body any) error {
	client, err := opts.client(cmd, auth)
	if err != nil {
		return err
	}
	result, err := client.Request(cmd.Context(), method, path, projectID, body)
	if err != nil {
		if projectID == "" {
			projectID, _ = cmd.Flags().GetString("project")
		}
		return friendlyError(cmd, opts, projectID, err)
	}
	return writeJSON(cmd, result)
}

func writeJSON(cmd *cobra.Command, data json.RawMessage) error {
	outputFormat, _ := cmd.Flags().GetString("output")
	switch outputFormat {
	case "json":
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return err
	case "yaml":
		converted, err := output.ConvertJSONToYAML(data)
		if err != nil {
			return fmt.Errorf("convert daemon response to YAML: %w", err)
		}
		_, err = cmd.OutOrStdout().Write(converted)
		return err
	case "table":
		return writeHuman(cmd, data)
	default:
		return fmt.Errorf("unsupported output format %q (use table, json, or yaml)", outputFormat)
	}
}

func newHealth(opts *options) *cobra.Command {
	return &cobra.Command{Use: "health", Short: "Check whether the local Connect daemon is reachable", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return runRequest(cmd, opts, false, http.MethodGet, "/v1/health", "", nil)
	}}
}

func newStatus(opts *options) *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Show your Connector, services, and local forwards", Long: "Show whether Connect is running for your project, the services you expose,\nand the local ports you forward. Use --output json for automation.", Example: "  datumctl connect status\n  datumctl connect --project PROJECT status --output json", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := project(cmd)
		if err != nil {
			return err
		}
		return runRequest(cmd, opts, true, http.MethodGet, "/v1/status", p, nil)
	}}
}

func newUp(opts *options) *cobra.Command {
	var credentialsFile string
	var auth string
	var name string
	longHelp, exampleHelp := upHelp(runtime.GOOS, daemonservice.SystemSetupTokenPath())
	cmd := &cobra.Command{Use: "up", Short: "Connect this device to your project", Long: longHelp, Example: exampleHelp, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if auth != "auto" && auth != "oidc" && auth != "stored" {
			return fmt.Errorf("--auth must be auto, oidc, or stored")
		}
		if credentialsFile != "" && auth != "auto" {
			return fmt.Errorf("--credentials-file cannot be combined with --auth %s", auth)
		}
		if name != "" && !validDeviceName(name) {
			return fmt.Errorf("--name must contain 1–63 lowercase letters, digits, or hyphens, and start and end with a letter or digit")
		}
		p, err := project(cmd)
		if err != nil {
			if guidedSetupEnabled(cmd, opts) && credentialsFile == "" && auth != "stored" {
				return hostSetup(cmd, strings.TrimSpace(os.Getenv("DATUM_SESSION")) == "")
			}
			return err
		}
		body := map[string]any{"project": p, "name_hint": deviceNameHint()}
		if name != "" {
			body["name"] = name
		}
		if err := addUpAuthentication(body, auth, credentialsFile); err != nil {
			if guidedSetupEnabled(cmd, opts) && auth == "oidc" && strings.TrimSpace(os.Getenv("DATUM_SESSION")) == "" {
				return hostSetup(cmd, true)
			}
			return err
		}
		if credentialsFile != "" {
			abs, err := filepath.Abs(credentialsFile)
			if err != nil {
				return fmt.Errorf("credentials file: %w", err)
			}
			if info, err := os.Stat(abs); err != nil {
				return fmt.Errorf("credentials file: %w", err)
			} else if info.IsDir() {
				return fmt.Errorf("credentials file %s is a directory", abs)
			}
			body["credentials_file"] = abs
		}
		if err := ensureDaemonForUp(cmd, opts); err != nil {
			return err
		}
		client, err := opts.client(cmd, true)
		if err != nil {
			return err
		}
		result, err := client.Request(cmd.Context(), http.MethodPost, "/v1/up", "", body)
		if err != nil {
			var response *connectapi.HTTPError
			if errors.As(err, &response) && response.Code == "credentials_required" && guidedSetupEnabled(cmd, opts) && credentialsFile == "" && auth != "stored" {
				return hostSetup(cmd, true)
			}
			return friendlyError(cmd, opts, p, err)
		}
		return writeJSON(cmd, result)
	}}
	credentialHelp := "OAuth refresh-token or service-account JSON file"
	authHelp := "Authentication source: auto (reuse saved, otherwise datumctl), oidc (replace with current session), or stored (reuse only)"
	if runtime.GOOS == "windows" {
		credentialHelp = "LocalSystem-readable Connector refresh-token or service-account JSON (normally supplied during daemon install)"
		authHelp = "Authentication source: auto (reuse service credentials), stored (reuse only); oidc is unavailable for the local Windows service"
	}
	cmd.Flags().StringVar(&credentialsFile, "credentials-file", "", credentialHelp)
	cmd.Flags().StringVar(&auth, "auth", "auto", authHelp)
	cmd.Flags().StringVar(&name, "name", "", "Unique device name for first enrollment (default: hostname); existing device names are preserved")
	return cmd
}

func upHelp(goos, setupToken string) (string, string) {
	if goos == "windows" {
		return "Connect this device to your project and restore its saved services and forwards.\nThe local Windows system daemon must already be running.\n\nWindows LocalSystem cannot use an interactive datumctl OIDC session. By default,\nup uses renewable Connector or service-account credentials copied into protected\nstate during daemon install. Use --credentials-file only for rotation from a\nLocalSystem-readable path, or --auth stored to require existing saved credentials.\nPass the protected local authorization token with --token-file.", "  datumctl connect up --token-file \"" + setupToken + "\"\n  datumctl connect up --auth stored --token-file \"" + setupToken + "\""
	}
	return "Connect this device to your project and restore its saved services and forwards.\nIn an interactive user terminal, up starts your local daemon and asks before\ninstalling a background service. It offers datumctl login and context selection\nwhen needed. You can also start directly with serve for guided first-time setup.\n\nBy default, up reuses saved credentials. On first setup, it uses your named\ndatumctl login session and your user permissions. The daemon pins that session;\nchanging your current datumctl context does not silently switch its identity.\nPrivate refresh credentials stay with datumctl. If the session expires, log in\nagain to the same named session before reconnecting.\n\nUse --name to choose a unique device name on first enrollment. Existing names\nare preserved. Use --auth oidc to explicitly replace saved authorization, or\n--auth stored to reuse it. Scripts, JSON/YAML output, explicit tokens, custom API\nURLs, and privileged daemons require explicit setup; they never prompt.\nFor unattended servers, use --credentials-file to import private service-account\nor Connector credential JSON instead.", "  datumctl connect serve localhost:8080\n  datumctl connect up\n  datumctl connect up --name scot-macbook\n  datumctl connect up --auth oidc\n  datumctl connect up --auth stored\n  datumctl connect up --credentials-file /path/to/credentials.json"
}

func newDown(opts *options) *cobra.Command {
	return &cobra.Command{Use: "down", Short: "Disconnect this project and stop its services and forwards", Long: "Disconnect this project without stopping the daemon or forgetting your device\nidentity. Saved services and forwards resume when you run datumctl connect up.", Example: "  datumctl connect down\n  datumctl connect up", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := project(cmd)
		if err != nil {
			return err
		}
		return runRequest(cmd, opts, true, http.MethodPost, "/v1/down", p, nil)
	}}
}

func newServe(opts *options) *cobra.Command {
	var public bool
	var hostname string
	var allow []string
	var protocol string
	cmd := &cobra.Command{Use: "serve HOST:PORT", Short: "Share an existing local service", Long: "Forward traffic to an existing service at HOST:PORT. HOST is the destination,\nnot a listen address; use localhost for a service running on this device.\nOn macOS/Linux, an interactive user terminal guides you through daemon setup,\nlogin, project selection, and first enrollment. If you previously ran down,\nserve asks before reconnecting and restoring saved services.\nScripts, explicit tokens, custom daemon URLs, JSON/YAML output, and Windows\nrequire explicit setup with datumctl connect up first.\n\nServices are private by default: project devices can connect, excluding gateway\nidentities approved by your Connector's class and aliases of those keys.\nUse --allow to select specific Connector names or public keys. Explicitly\nallowing a gateway can expose your service through that gateway's ingress.\nUse --public for public HTTP ingress to a TCP service. Public services cannot\nuse --allow or --protocol udp and require a compatible platform gateway.\n\nThe daemon keeps serving after this command exits. Use status to inspect\nservices and unserve to remove one.", Example: "  datumctl connect serve localhost:8080\n  datumctl connect serve localhost:22 --allow TEAMMATE_CONNECTOR\n  datumctl connect serve localhost:8080 --public\n  datumctl connect serve localhost:5353 --protocol udp", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateEndpoint(args[0]); err != nil {
			return err
		}
		if hostname != "" && !public {
			return fmt.Errorf("--hostname requires --public")
		}
		var err error
		protocol, err = parseProtocol(protocol)
		if err != nil {
			return err
		}
		if public && protocol == "udp" {
			return fmt.Errorf("--public supports HTTP ingress over TCP only; remove --public to share UDP privately")
		}
		if public && cmd.Flags().Changed("allow") {
			return fmt.Errorf("--public cannot be combined with --allow; remove --public to restrict access to specific Connectors")
		}
		if handled, err := prepareServe(cmd, opts); handled || err != nil {
			return err
		}
		p, err := project(cmd)
		if err != nil {
			return err
		}
		if allow == nil {
			allow = []string{}
		}
		body := map[string]any{"endpoint": args[0], "protocol": protocol, "public": public, "allow": allow}
		if hostname != "" {
			body["hostname"] = hostname
		}
		return runRequest(cmd, opts, true, http.MethodPost, "/v1/services", p, body)
	}}
	cmd.Flags().BoolVar(&public, "public", false, "Request public HTTP ingress (TCP only; default is private)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "Public hostname (requires --public)")
	cmd.Flags().StringSliceVar(&allow, "allow", nil, "Allow these Connector names or keys (default: project devices except approved gateways)")
	cmd.Flags().StringVar(&protocol, "protocol", "tcp", "Transport protocol: tcp or udp")
	return cmd
}

func newUnserve(opts *options) *cobra.Command {
	return &cobra.Command{Use: "unserve HOST:PORT|NAME", Short: "Stop sharing a service and remove its saved configuration", Long: "Remove a service by its destination or the service name shown by status.\nIf TCP and UDP share the same destination, use the service name.\nThis does not stop your local application.", Example: "  datumctl connect unserve localhost:8080\n  datumctl connect status\n  datumctl connect unserve service-EXAMPLE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := project(cmd)
		if err != nil {
			return err
		}
		return runRequest(cmd, opts, true, http.MethodDelete, "/v1/services/"+url.PathEscape(args[0]), p, nil)
	}}
}

func newDial(opts *options) *cobra.Command {
	var bind uint16
	var protocol string
	cmd := &cobra.Command{Use: "dial CONNECTOR:PORT", Short: "Forward a local port to a service on another Connector", Long: "Open a loopback-only local port that forwards to a service shared by another\nConnector in your project. CONNECTOR is its name or public key, not an IP\naddress. Its service must allow your Connector. Use the same protocol as serve.\n\nRun datumctl connect up first. If you omit --bind, the daemon chooses a port\nand reports it. Traffic connects when your application uses that local port.\nThe forward persists after this command exits; use hangup LOCALPORT to remove it.", Example: "  datumctl connect dial SERVER_CONNECTOR:22 --bind 2222\n  ssh -p 2222 localhost\n  datumctl connect dial SERVER_CONNECTOR:5353 --protocol udp --bind 5353\n  datumctl connect hangup 2222", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		connector, port, err := splitConnector(args[0])
		if err != nil {
			return err
		}
		protocol, err = parseProtocol(protocol)
		if err != nil {
			return err
		}
		p, err := project(cmd)
		if err != nil {
			return err
		}
		return runRequest(cmd, opts, true, http.MethodPost, "/v1/dials", p, map[string]any{"connector": connector, "port": port, "bind": bind, "protocol": protocol})
	}}
	cmd.Flags().Uint16Var(&bind, "bind", 0, "Local port (0 lets the daemon choose)")
	cmd.Flags().StringVar(&protocol, "protocol", "tcp", "Transport protocol: tcp or udp")
	return cmd
}

func newHangup(opts *options) *cobra.Command {
	return &cobra.Command{Use: "hangup LOCALPORT", Short: "Close a local forward and remove its saved configuration", Long: "Close the local port created by dial. Use the port reported by dial or status,\nnot the remote service's port. This does not remove the remote service.", Example: "  datumctl connect hangup 2222", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		// Zero identifies saved ephemeral intent that failed before getting a port.
		port, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil {
			return fmt.Errorf("local port: %w", err)
		}
		p, err := project(cmd)
		if err != nil {
			return err
		}
		return runRequest(cmd, opts, true, http.MethodDelete, "/v1/dials/"+strconv.Itoa(int(port)), p, nil)
	}}
}

func newJoin(opts *options) *cobra.Command  { return networkCommand(opts, "join", http.MethodPost) }
func newLeave(opts *options) *cobra.Command { return networkCommand(opts, "leave", http.MethodDelete) }

func networkCommand(opts *options, name, method string) *cobra.Command {
	return &cobra.Command{Use: name + " NETWORK", Short: strings.Title(name) + " an approved local IP network (native preview)", Long: "Attach or detach an explicitly approved local CONNECT-IP network.\nRequires an enrolled project and a supported native daemon started with --local-ip-config.\nAttachments are ephemeral and disappear on down or daemon restart; this does not create a production NetworkBinding.\nUse serve and dial for individual TCP or UDP services when CONNECT-IP is unavailable.", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := project(cmd)
		if err != nil {
			return err
		}
		path := "/v1/networks"
		var body any = map[string]string{"network": args[0]}
		if method == http.MethodDelete {
			path += "/" + url.PathEscape(args[0])
			body = nil
		}
		return runRequest(cmd, opts, true, method, path, p, body)
	}}
}

func newPing(opts *options) *cobra.Command {
	return &cobra.Command{Use: "ping CONNECTOR", Short: "Check whether another Connector is reachable", Long: "Probe another Connector by name or public key in your project.\nThis checks Connector connectivity, not a particular service or application.\nArbitrary IP addresses and VPC ICMP ping are not supported in this preview.", Example: "  datumctl connect ping SERVER_CONNECTOR", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := project(cmd)
		if err != nil {
			return err
		}
		return runRequest(cmd, opts, true, http.MethodPost, "/v1/ping", p, map[string]string{"address": args[0]})
	}}
}

func validateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("endpoint must be HOST:PORT (IPv6 must use brackets): %w", err)
	}
	if host == "" {
		return fmt.Errorf("endpoint host is required")
	}
	if _, err := parsePort(port); err != nil {
		return fmt.Errorf("endpoint port %q: %w", port, err)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return fmt.Errorf("%s is a listen address, not a service destination; use localhost:%s to reach your local service", host, port)
	}
	return nil
}

func splitConnector(value string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		idx := strings.LastIndexByte(value, ':')
		if idx <= 0 || strings.Contains(value[:idx], ":") {
			return "", 0, fmt.Errorf("dial target must be CONNECTOR:PORT, for example SERVER_CONNECTOR:22")
		}
		host, portText = value[:idx], value[idx+1:]
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, fmt.Errorf("connector is required")
	}
	port, err := parsePort(portText)
	if err != nil {
		return "", 0, fmt.Errorf("connector port %q: %w", portText, err)
	}
	return host, port, nil
}

func parsePort(value string) (uint16, error) {
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("must be an integer from 1 to 65535")
	}
	return uint16(n), nil
}

func parseProtocol(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "tcp" && value != "udp" {
		return "", fmt.Errorf("protocol must be tcp or udp")
	}
	return value, nil
}

func newDaemon() *cobra.Command {
	cmd := &cobra.Command{Use: "daemon", Short: "Manage the local Datum Connect daemon service"}
	cmd.AddCommand(daemonservice.InstallCommand(), daemonservice.UninstallCommand(), daemonservice.StartCommand(), daemonservice.StopCommand(), daemonservice.StatusCommand())
	return cmd
}
