package commands

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
	"go.datum.net/datumctl/plugin"
)

func setupCommand(project string) string {
	if project == "" || project == strings.TrimSpace(plugin.Context().Project) {
		return "datumctl connect up"
	}
	return fmt.Sprintf("datumctl connect up --project %q", project)
}

func friendlyError(cmd *cobra.Command, opts *options, projectID string, err error) error {
	var transport *connectapi.TransportError
	if errors.As(err, &transport) {
		if transport.Timeout {
			return fmt.Errorf("the Connect daemon did not respond in time. The operation may still be running.\nCheck: datumctl connect status --project %q\nRetry with --verbose for connection diagnostics", projectID)
		}
		return fmt.Errorf("cannot reach the Connect daemon at %s.\nCheck: datumctl connect daemon status\nIf stopped: datumctl connect daemon start\nIf not installed: datumctl connect daemon install\nRetry with --verbose for connection diagnostics", transport.URL)
	}
	var response *connectapi.HTTPError
	if !errors.As(err, &response) {
		return err
	}
	if opts.verbose {
		fmt.Fprintf(cmd.ErrOrStderr(), "connect: %v\n", response)
	}
	switch response.Code {
	case "local_ip_approval_required", "local_ip_grant_mismatch", "local_ip_gateway_approval_required", "local_ip_gateway_setup_failed", "local_ip_handshake_failed", "local_ip_datagrams_unsupported", "local_ip_datagram_mtu_insufficient":
		return fmt.Errorf("%s\nRetry with --verbose for diagnostics", strings.TrimSpace(response.Message))
	case "project_not_configured", "credentials_required":
		return fmt.Errorf("Connect is not set up for project %q.\n\nConnect this device first:\n  %s\n\nIf you have not signed in, run `datumctl login`, then run the command above through datumctl.\nFor unattended servers, you can supply --credentials-file PATH.\nRun `datumctl connect up --help` for details", projectID, setupCommand(projectID))
	case "project_down":
		return fmt.Errorf("Connect is down for project %q.\nRun: %s", projectID, setupCommand(projectID))
	}
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("the local Connect daemon did not accept your token. This is local daemon authentication, not your Datum cloud login.\nSupply a valid token with --token-file PATH or DATUM_CONNECT_TOKEN. Retry with --verbose for diagnostics")
	case http.StatusForbidden:
		return fmt.Errorf("your local daemon token does not permit this operation for project %q.\nAsk the daemon administrator for a token with the required project and operation scope.\nRetry with --verbose for diagnostics", projectID)
	default:
		return fmt.Errorf("%s\nRetry with --verbose for diagnostics", strings.TrimSpace(response.Message))
	}
}
