package commands

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
)

func TestFriendlySetupError(t *testing.T) {
	cmd := &cobra.Command{}
	err := friendlyError(cmd, &options{}, "my-project", &connectapi.HTTPError{StatusCode: 404, Message: "internal API wording", Code: "project_not_configured", RequestID: "hidden-id"})
	for _, want := range []string{`project "my-project"`, `datumctl connect up --project "my-project"`, "datumctl login", "up --help"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing %q in %v", want, err)
		}
	}
	for _, unwanted := range []string{"HTTP", "hidden-id", "internal API"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Fatalf("leaked %q in %v", unwanted, err)
		}
	}
}

func TestFriendlyErrorsPreserveVerboseCorrelation(t *testing.T) {
	cmd := &cobra.Command{}
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	err := friendlyError(cmd, &options{verbose: true}, "p", &connectapi.HTTPError{StatusCode: 403, Message: "scope denied", RequestID: "req-123"})
	if !strings.Contains(err.Error(), "local daemon token") {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "req-123") || !strings.Contains(stderr.String(), "HTTP 403") {
		t.Fatal(stderr.String())
	}
}

func TestFriendlyTransportError(t *testing.T) {
	err := friendlyError(&cobra.Command{}, &options{}, "p", &connectapi.TransportError{URL: "http://127.0.0.1:47780", Cause: errors.New("opaque network internals")})
	if !strings.Contains(err.Error(), "datumctl connect daemon start") || strings.Contains(err.Error(), "opaque") {
		t.Fatal(err)
	}
}

func TestServiceConflictKeepsRecoveryWithoutDiagnosticsHint(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		cmd := &cobra.Command{}
		var stderr bytes.Buffer
		cmd.SetErr(&stderr)
		message := "Cannot share datum.net:443: TCP port 443 is already shared as google.com:443.\nNothing changed.\n\nTo replace the existing share, stop it first:\n  datumctl connect unserve google.com:443 --project datum-cloud\nThen run your serve command again."
		err := friendlyError(cmd, &options{verbose: verbose}, "datum-cloud", &connectapi.HTTPError{StatusCode: 409, Code: "service_conflict", Message: message, RequestID: "req-conflict"})
		if err.Error() != message {
			t.Fatalf("unexpected conflict output: %v", err)
		}
		if strings.Contains(stderr.String(), "req-conflict") != verbose {
			t.Fatalf("verbose correlation = %q", stderr.String())
		}
	}
}

func TestNetworkApprovalErrorDoesNotBlameTheLocalToken(t *testing.T) {
	for _, code := range []string{"local_ip_approval_required", "local_ip_grant_mismatch", "local_ip_gateway_approval_required", "local_ip_gateway_setup_failed", "local_ip_handshake_failed", "local_ip_datagrams_unsupported", "local_ip_datagram_mtu_insufficient"} {
		err := friendlyError(&cobra.Command{}, &options{}, "p", &connectapi.HTTPError{StatusCode: 403, Code: code, Message: "Ask the gateway operator to correct the approved routes"})
		if !strings.Contains(err.Error(), "gateway operator") || strings.Contains(err.Error(), "local daemon token") {
			t.Fatal(err)
		}
	}
}

func TestMissingTokenErrorKeepsNotExistIdentity(t *testing.T) {
	_, err := readToken(t.TempDir() + "/missing.token")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing token identity lost: %v", err)
	}
}

func TestInvalidOutputFailsBeforeAuthenticationOrRequest(t *testing.T) {
	root := &cobra.Command{Use: "connect", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().String("output", "table", "")
	root.PersistentFlags().String("project", "p", "")
	Add(root)
	root.SetArgs([]string{"serve", "localhost:800", "--output", "typo"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf("error = %v", err)
	}
}
