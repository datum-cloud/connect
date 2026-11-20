package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	"go.datum.net/connect-controller/internal/controller"
	"go.datum.net/connect-controller/internal/credentials"
	"go.datum.net/connect-controller/internal/endpoints"
	cloud "go.datum.net/galactic/api/cloud/v1alpha1"
	galactic "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/pkg/masquegrant"
	consumer "go.miloapis.com/service-catalog/pkg/multicluster-runtime/consumer"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
)

type authenticatedConnector string

func (connector authenticatedConnector) Authenticate(context.Context, string) (string, error) {
	return string(connector), nil
}

type credentialServer struct {
	Server      *http.Server
	Certificate string
	Key         string
}

func (server *credentialServer) NeedLeaderElection() bool { return false }

func (server *credentialServer) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Server.Shutdown(shutdown)
	}()
	err := server.Server.ListenAndServeTLS(server.Certificate, server.Key)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func setupCredentials(mgr mcmanager.Manager, service *endpoints.Service, config endpoints.Config, options endpointFlags, projectConfig *rest.Config) error {
	if err := galactic.AddToScheme(scheme); err != nil {
		return err
	}
	if err := cloud.AddToScheme(scheme); err != nil {
		return err
	}
	if err := authorizationv1.AddToScheme(scheme); err != nil {
		return err
	}
	issuer := &credentials.ManagedIssuer{Project: service.Reconciler.Project, Namespace: service.Namespace, RuntimeNamespace: options.RuntimeNamespace, Now: time.Now, Authorities: map[string]credentials.GrantAPI{}, Cells: map[string]client.Reader{}}
	for name, cell := range config.Cells {
		if cell.GrantKubeconfig == "" {
			continue
		}
		config, err := restConfig(cell.GrantKubeconfig)
		if err != nil {
			return err
		}
		grantClient, err := client.New(config, client.Options{Scheme: scheme})
		if err != nil {
			return err
		}
		issuer.Authorities[name] = masquegrant.New(grantClient, options.RuntimeNamespace, name)
		issuer.Cells[name] = grantClient
	}
	valid := func(ctx context.Context, receipt *connect.ConnectGrant) (bool, error) {
		endpoint := &connect.ConnectEndpoint{}
		if err := issuer.Project.Get(ctx, client.ObjectKey{Namespace: service.Namespace, Name: receipt.Spec.EndpointName}, endpoint); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		if endpoint.UID == "" || string(endpoint.UID) != receipt.Spec.EndpointUID || endpoint.Spec.Lifecycle != "Active" {
			return false, nil
		}
		vpc, err := service.ResolveVPC(receipt.Spec.NetworkUID, receipt.Spec.Cell)
		if err != nil || vpc != receipt.Spec.VPC {
			return false, nil
		}
		customer, err := service.Customer(ctx, endpoint.Spec.CustomerProject)
		if err != nil {
			return false, err
		}
		return controller.GrantStillAuthorized(ctx, customer, endpoint, receipt)
	}
	if err := mgr.GetLocalManager().Add(&credentials.GrantSweeper{Issuer: issuer, Valid: valid}); err != nil {
		return err
	}
	if options.CredentialAddress == "" {
		return nil
	}
	if options.CredentialCertificate == "" || options.CredentialKey == "" {
		return fmt.Errorf("credential broker requires TLS")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apis/resourcemanager.miloapis.com/v1alpha1/projects/{project}/control-plane/apis/connect.datumapis.com/v1alpha1/namespaces/{namespace}/connectnetworkbindings/{binding}/connection-credentials", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Pragma", "no-cache")
		deny := func() { http.Error(writer, "Forbidden", http.StatusForbidden) }
		if request.URL.RawQuery != "" {
			deny()
			return
		}
		token, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
		if !found || token == "" {
			deny()
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
		defer cancel()
		project, namespace, bindingName := request.PathValue("project"), request.PathValue("namespace"), request.PathValue("binding")
		if len(validation.IsDNS1123Subdomain(project)) != 0 || len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(bindingName)) != 0 {
			deny()
			return
		}
		callerConfig, err := consumer.ProjectRestConfig(rest.AnonymousClientConfig(projectConfig), project)
		if err != nil {
			deny()
			return
		}
		callerConfig.BearerToken = token
		caller, err := client.New(callerConfig, client.Options{Scheme: scheme})
		if err != nil {
			deny()
			return
		}
		access := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: namespace, Verb: "create", Group: connect.GroupVersion.Group, Version: connect.GroupVersion.Version, Resource: "connectnetworkbindings", Subresource: "connection-credentials", Name: bindingName}}}
		if err := caller.Create(ctx, access); err != nil || !access.Status.Allowed || access.Status.Denied {
			deny()
			return
		}
		binding := &connect.ConnectNetworkBinding{}
		if err := caller.Get(ctx, client.ObjectKey{Namespace: namespace, Name: bindingName}, binding); err != nil {
			deny()
			return
		}
		customer, err := service.Customer(ctx, project)
		if err != nil {
			http.Error(writer, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		broker := &credentials.Broker{Resolver: controller.ManagedBindingResolver{Customer: customer, Service: service, ProjectName: project, Namespace: namespace, Now: time.Now}, Authenticator: authenticatedConnector(binding.Spec.ConnectorRef), Issuer: issuer, Now: time.Now}
		copy := request.Clone(ctx)
		copy.URL.Path = "/connectnetworkbindings/" + bindingName + "/connection-credentials"
		broker.ServeHTTP(writer, copy)
	})
	return mgr.GetLocalManager().Add(&credentialServer{Server: &http.Server{Addr: options.CredentialAddress, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16384}, Certificate: options.CredentialCertificate, Key: options.CredentialKey})
}
