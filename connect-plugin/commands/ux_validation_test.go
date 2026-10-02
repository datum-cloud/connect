package commands

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestServeRejectsInvalidDestinationWithRecovery(t *testing.T) {
	for _, tt := range []struct {
		endpoint string
		want     string
	}{
		{"0.0.0.0:800", "use localhost:800"},
		{"[::]:800", "use localhost:800"},
		{"localhost:0", `endpoint port "0"`},
		{"localhost:65536", `endpoint port "65536"`},
	} {
		t.Run(tt.endpoint, func(t *testing.T) {
			err := validateEndpoint(tt.endpoint)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestServeValidatesPublicFlagsBeforeProjectOrAuthentication(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"localhost:800", "--public", "--protocol", "udp"}, "--public supports HTTP ingress over TCP only"},
		{[]string{"localhost:800", "--public", "--allow", "teammate"}, "--public cannot be combined with --allow"},
		{[]string{"localhost:800", "--public", "--allow="}, "--public cannot be combined with --allow"},
		{[]string{"localhost:800", "--hostname", "example.com"}, "--hostname requires --public"},
	} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			cmd := newServe(&options{})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestHelpExplainsScopeAndPreviewLimitations(t *testing.T) {
	upWants := []string{"Private refresh credentials stay with datumctl", "--credentials-file", "--auth oidc", "same named session"}
	if runtime.GOOS == "windows" {
		upWants = []string{"LocalSystem", "service-account", "--credentials-file", "--token-file"}
	}
	for _, tt := range []struct {
		cmd  *cobra.Command
		want []string
	}{
		{newServe(&options{}), []string{"project devices can connect", "approved by your Connector's class", "allowing a gateway can expose", "not a listen address", "after this command exits", "datumctl connect serve localhost:8080 --public"}},
		{newDial(&options{}), []string{"loopback-only", "Traffic connects when your application", "hangup LOCALPORT"}},
		{newUp(&options{}), upWants},
		{newPing(&options{}), []string{"CONNECTOR", "ICMP ping are not supported"}},
		{newJoin(&options{}), []string{"--peer", "Administrator approval", "explicit rejoin", "Scripts never prompt or elevate"}},
		{newLeave(&options{}), []string{"--local-ip-config", "serve and dial", "ephemeral"}},
	} {
		t.Run(tt.cmd.Name(), func(t *testing.T) {
			var out bytes.Buffer
			tt.cmd.SetOut(&out)
			tt.cmd.SetArgs([]string{"--help"})
			if err := tt.cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("help missing %q: %s", want, out.String())
				}
			}
		})
	}
}

func TestUpHelpIsPlatformSpecific(t *testing.T) {
	long, example := upHelp("windows", `C:\ProgramData\Datum\Connect\daemon_auth\setup.token`)
	for _, want := range []string{"LocalSystem", "service-account", "--credentials-file", "--token-file"} {
		if !strings.Contains(long+example, want) {
			t.Errorf("Windows up help lacks %q", want)
		}
	}
	unixLong, _ := upHelp("darwin", "/unused")
	if !strings.Contains(unixLong, "--auth oidc") {
		t.Fatal("Unix up help lost OIDC guidance")
	}
}
