package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"go.datum.net/connect-controller/internal/endpoints"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"
)

type endpointFlags struct {
	CredentialAddress     string
	CredentialCertificate string
	CredentialKey         string
	Enabled               bool
	Provision             bool
	ProjectConfig         string
	Namespace             string
	Domain                string
	Zone                  string
	KarmadaConfig         string
	CertificateConfig     string
	CertificateNamespace  string
	RuntimeNamespace      string
	ConfigFile            string
}

func (options *endpointFlags) register() {
	flag.StringVar(&options.CredentialAddress, "credential-listen-address", "", "optional TLS credential broker address")
	flag.StringVar(&options.CredentialCertificate, "credential-tls-cert", "", "credential broker TLS certificate file")
	flag.StringVar(&options.CredentialKey, "credential-tls-key", "", "credential broker TLS key file")
	flag.BoolVar(&options.Enabled, "managed-endpoints", false, "reconcile durable managed endpoints")
	flag.BoolVar(&options.Provision, "endpoint-provisioning", true, "allow new reservations; disabling preserves renewal and cleanup")
	flag.StringVar(&options.ProjectConfig, "endpoint-project-kubeconfig", "", "explicit dedicated service-project kubeconfig")
	flag.StringVar(&options.Namespace, "endpoint-namespace", "", "service-project endpoint namespace")
	flag.StringVar(&options.Domain, "endpoint-domain", "", "managed DNS domain")
	flag.StringVar(&options.Zone, "endpoint-zone", "", "existing shared DNSZone name")
	flag.StringVar(&options.KarmadaConfig, "karmada-kubeconfig", "", "Karmada delivery kubeconfig")
	flag.StringVar(&options.CertificateConfig, "certificate-kubeconfig", "", "read-only central stored certificate kubeconfig")
	flag.StringVar(&options.CertificateNamespace, "certificate-namespace", "", "stored certificate namespace")
	flag.StringVar(&options.RuntimeNamespace, "endpoint-runtime-namespace", "masque-system", "existing shared provider namespace")
	flag.StringVar(&options.ConfigFile, "endpoint-config", "", "operator capacity, cell readers and external probe JSON configuration")
}

func (options endpointFlags) setup(mgr mcmanager.Manager, root client.Client, projectConfig *rest.Config) (*endpoints.Service, error) {
	if !options.Enabled {
		return nil, nil
	}
	if options.ProjectConfig == "" || options.Namespace == "" || options.Domain == "" || options.Zone == "" || options.KarmadaConfig == "" || options.CertificateConfig == "" || options.CertificateNamespace == "" || options.ConfigFile == "" {
		return nil, fmt.Errorf("managed endpoints require explicit project, certificate, Karmada and configuration flags")
	}
	encoded, err := os.ReadFile(options.ConfigFile)
	if err != nil {
		return nil, err
	}
	var config endpoints.Config
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	makeClient := func(path string) (client.Client, error) {
		if path == "" {
			return nil, fmt.Errorf("explicit kubeconfig required")
		}
		rest, err := restConfig(path)
		if err != nil {
			return nil, err
		}
		return client.New(rest, client.Options{Scheme: scheme})
	}
	project, err := makeClient(options.ProjectConfig)
	if err != nil {
		return nil, err
	}
	certificates, err := makeClient(options.CertificateConfig)
	if err != nil {
		return nil, err
	}
	karmada, err := makeClient(options.KarmadaConfig)
	if err != nil {
		return nil, err
	}
	cells := map[string]client.Client{}
	for name, cell := range config.Cells {
		reader, err := makeClient(cell.Kubeconfig)
		if err != nil {
			return nil, err
		}
		cells[name] = reader
	}
	for _, capacity := range config.Capacity {
		assignment := capacity.Assignment
		if capacity.Metro == "" || assignment.Cell == "" || assignment.Provider == "" || assignment.Frontend == "" || cells[assignment.Cell] == nil {
			return nil, fmt.Errorf("incomplete operator capacity mapping")
		}
	}
	seenReachability := map[string]bool{}
	for _, mapping := range config.Reachability {
		key := mapping.NetworkUID + "/" + mapping.Cell
		if mapping.NetworkUID == "" || cells[mapping.Cell] == nil || mapping.VPC.Name == "" || mapping.VPC.Namespace == "" || mapping.VPC.UID == "" || seenReachability[key] {
			return nil, fmt.Errorf("incomplete or ambiguous operator reachability mapping")
		}
		seenReachability[key] = true
	}
	sort.Slice(config.Capacity, func(left, right int) bool {
		return config.Capacity[left].Assignment.Cell < config.Capacity[right].Assignment.Cell
	})
	driver := &endpoints.KubernetesDriver{Project: project, Certificates: certificates, Karmada: karmada, Cells: cells, CertificateNamespace: options.CertificateNamespace, RuntimeNamespace: options.RuntimeNamespace, Zone: options.Zone, Domain: options.Domain, Now: time.Now}
	if config.ProbeURL != "" {
		driver.ProbeEndpoint, err = endpoints.HTTPProbe(config.ProbeURL, &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, time.Now)
		if err != nil {
			return nil, err
		}
	}
	service := &endpoints.Service{Reconciler: &endpoints.Reconciler{Project: project, Driver: driver, Now: time.Now, ExpiryMargin: 5 * time.Minute, DNSDrain: 2 * time.Minute}, Root: root, Namespace: options.Namespace, Domain: options.Domain, Capacity: config.Capacity, Reachability: config.Reachability, Provision: options.Provision}
	service.Customer = func(ctx context.Context, project string) (client.Client, error) {
		cluster, err := mgr.GetCluster(ctx, multicluster.ClusterName(project))
		if err != nil {
			return nil, err
		}
		return client.New(cluster.GetConfig(), client.Options{Scheme: scheme})
	}
	if err := mgr.GetLocalManager().Add(service); err != nil {
		return nil, err
	}
	if err := setupCredentials(mgr, service, config, options, projectConfig); err != nil {
		return nil, err
	}
	return service, nil
}
