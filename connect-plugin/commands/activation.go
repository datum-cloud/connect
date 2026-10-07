package commands

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"go.datum.net/datumctl/plugin"
	"go.miloapis.com/service-catalog/pkg/activation"
	"k8s.io/client-go/rest"
)

const connectServiceName = "connect.datumapis.com"

// connectServiceGateRequired identifies commands that establish or use a
// cloud-side Connect session. Inspection, cleanup, and local daemon lifecycle
// commands remain usable when service access is pending or unavailable.
func connectServiceGateRequired(cmd *cobra.Command) bool {
	switch cmd.Name() {
	case "up", "serve", "dial", "join", "ping":
		return true
	default:
		return false
	}
}

// runConnectServiceGate uses the service-catalog CLI SDK before a command
// reaches the daemon. Self-service catalog entries are enabled immediately;
// provider-gated entries use the SDK's interactive request flow.
func runConnectServiceGate(cmd *cobra.Command, project string) error {
	if project == "" {
		// Let the command's existing project-selection flow produce the more
		// useful error or redispatch through datumctl's context picker.
		return nil
	}

	host := plugin.Context()
	if host.APIHost == "" || host.CredentialsHelper == "" {
		// Connect also supports explicitly configured standalone/automation
		// paths. They have no datumctl user session with which to inspect or
		// mutate service access, so preserve their existing daemon-side flow.
		return nil
	}

	return defaultConnectServiceActivation().run(cmd, project)
}

type connectServiceActivation struct {
	resolveService       func(context.Context) (activation.ServiceInfo, error)
	newEntitlementClient func(string) (activation.EntitlementClient, error)
	io                   func(*cobra.Command) activation.IOStreams
}

func defaultConnectServiceActivation() connectServiceActivation {
	return connectServiceActivation{
		resolveService:       resolveConnectService,
		newEntitlementClient: newConnectEntitlementClient,
		io:                   connectActivationIO,
	}
}

func (a connectServiceActivation) run(cmd *cobra.Command, project string) error {
	service, err := a.resolveService(cmd.Context())
	if err != nil {
		return err
	}
	client, err := a.newEntitlementClient(project)
	if err != nil {
		return err
	}

	io := connectActivationIO(cmd)
	if a.io != nil {
		io = a.io(cmd)
	}
	return (activation.Gate{
		Service: service,
		Client:  client,
		IO:      io,
		Project: project,
	}).Run(cmd.Context())
}

func connectActivationIO(cmd *cobra.Command) activation.IOStreams {
	return activation.IOStreams{
		In:  cmd.InOrStdin(),
		Out: cmd.OutOrStdout(),
		Err: cmd.ErrOrStderr(),
	}
}

// resolveConnectService reads the live catalog entry so enablement policy and
// user-facing service metadata stay owned by service-catalog.
func resolveConnectService(ctx context.Context) (activation.ServiceInfo, error) {
	cfg, err := connectRESTConfig(func(apiHost string) (string, error) {
		return connectAPIBaseURL(apiHost)
	})
	if err != nil {
		return activation.ServiceInfo{}, err
	}
	client, err := activation.NewCatalogRESTClient(cfg)
	if err != nil {
		return activation.ServiceInfo{}, fmt.Errorf("building service catalog client: %w", err)
	}
	services, err := client.ListServices(ctx)
	if err != nil {
		return activation.ServiceInfo{}, fmt.Errorf("looking up the Connect service: %w", err)
	}
	return activation.FindService(services, connectServiceName)
}

func newConnectEntitlementClient(project string) (activation.EntitlementClient, error) {
	cfg, err := connectRESTConfig(func(apiHost string) (string, error) {
		baseURL, err := connectAPIBaseURL(apiHost)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s/apis/resourcemanager.miloapis.com/v1alpha1/projects/%s/control-plane", baseURL, url.PathEscape(project)), nil
	})
	if err != nil {
		return nil, err
	}
	client, err := activation.NewRESTClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("building Connect service entitlement client: %w", err)
	}
	return client, nil
}

func connectAPIBaseURL(apiHost string) (string, error) {
	raw := strings.TrimSpace(apiHost)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid DATUM_API_HOST %q: %w", apiHost, err)
	}
	if (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid DATUM_API_HOST %q", apiHost)
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return parsed.String(), nil
}

func connectRESTConfig(hostURL func(string) (string, error)) (*rest.Config, error) {
	host := plugin.Context()
	if host.APIHost == "" {
		return nil, fmt.Errorf("DATUM_API_HOST is not set; run this command through datumctl")
	}
	token, err := plugin.Token()
	if err != nil {
		return nil, fmt.Errorf("getting datumctl credentials: %w", err)
	}
	resolvedHost, err := hostURL(host.APIHost)
	if err != nil {
		return nil, err
	}
	return &rest.Config{Host: resolvedHost, BearerToken: token}, nil
}
