package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	"go.datum.net/connect-controller/internal/endpointprobe"
	"go.datum.net/connect-controller/internal/endpoints"
	coordination "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var address, certificate, key, ca, project, configPath string
	probe := &endpointprobe.Server{}
	flag.StringVar(&address, "listen-address", ":8443", "HTTPS listen address")
	flag.StringVar(&certificate, "tls-cert", "", "serving certificate")
	flag.StringVar(&key, "tls-key", "", "serving key")
	flag.StringVar(&ca, "client-ca", "", "dedicated trusted client CA")
	flag.StringVar(&project, "endpoint-project-kubeconfig", "", "pinned read-only service Project client")
	flag.StringVar(&probe.Namespace, "endpoint-namespace", "", "reservation namespace")
	flag.StringVar(&probe.RuntimeNamespace, "endpoint-runtime-namespace", "masque-system", "registration namespace")
	flag.StringVar(&probe.Domain, "endpoint-domain", "", "trusted managed hostname suffix")
	flag.StringVar(&configPath, "endpoint-config", "", "operator capacity and selected cell clients")
	flag.Parse()
	if certificate == "" || key == "" || ca == "" || probe.Namespace == "" || probe.RuntimeNamespace == "" || probe.Domain == "" || configPath == "" {
		return fmt.Errorf("explicit TLS, namespaces, domain and configuration required")
	}
	pool, err := endpointprobe.CertificatePool(ca)
	if err != nil {
		return err
	}
	encoded, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var config endpoints.Config
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("configuration contains trailing data")
	}
	scheme := runtime.NewScheme()
	if err := connect.AddToScheme(scheme); err != nil {
		return err
	}
	if err := coordination.AddToScheme(scheme); err != nil {
		return err
	}
	makeClient := func(path string) (client.Client, error) {
		if path == "" {
			return nil, fmt.Errorf("explicit kubeconfig required")
		}
		config, err := clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			return nil, err
		}
		config.Timeout = 3 * time.Second
		return client.New(config, client.Options{Scheme: scheme})
	}
	probe.Project, err = makeClient(project)
	if err != nil {
		return err
	}
	probe.Capacity = config.Capacity
	probe.Driver = &endpoints.KubernetesDriver{Cells: map[string]client.Client{}, RuntimeNamespace: probe.RuntimeNamespace, Now: time.Now}
	for name, cell := range config.Cells {
		probe.Driver.Cells[name], err = makeClient(cell.Kubeconfig)
		if err != nil {
			return err
		}
	}
	server := &http.Server{Addr: address, Handler: probe.Handler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}}
	return server.ListenAndServeTLS(certificate, key)
}
