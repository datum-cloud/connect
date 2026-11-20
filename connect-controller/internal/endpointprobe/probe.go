package endpointprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	connect "go.datum.net/connect-controller/api/v1alpha1"
	"go.datum.net/connect-controller/internal/endpoints"
	"golang.org/x/net/http2"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Server struct {
	Project          client.Reader
	Driver           *endpoints.KubernetesDriver
	Namespace        string
	RuntimeNamespace string
	Domain           string
	Capacity         []endpoints.Capacity
	Check            func(context.Context, string, string, string) error
}

func (server *Server) Handler() http.Handler {
	semaphore := make(chan struct{}, 8)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /endpoints/{namespace}/{name}", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
		default:
			http.Error(writer, "probe capacity exceeded", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), 4*time.Second)
		defer cancel()
		name := request.PathValue("name")
		if request.URL.RawQuery != "" || request.PathValue("namespace") != server.RuntimeNamespace || len(validation.IsDNS1123Subdomain(name)) != 0 {
			http.Error(writer, "invalid probe request", http.StatusBadRequest)
			return
		}
		report, err := server.observe(ctx, name)
		if err != nil {
			http.Error(writer, "endpoint verification failed", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(report)
	})
	return mux
}

func (server *Server) observe(ctx context.Context, name string) (*endpoints.ProbeReport, error) {
	endpoint := &connect.ConnectEndpoint{}
	key := client.ObjectKey{Namespace: server.Namespace, Name: name}
	if err := server.Project.Get(ctx, key, endpoint); err != nil {
		return nil, err
	}
	if endpoint.UID == "" || endpoint.DeletionTimestamp != nil || endpoint.Spec.Lifecycle != "Active" || endpoint.Status.Revision <= 0 || endpoint.Status.CertificateRevision == "" {
		return nil, fmt.Errorf("inactive reservation")
	}
	hostname := endpoint.Spec.Hostname
	if server.Domain == "" || hostname == server.Domain || !strings.HasSuffix(hostname, "."+server.Domain) || len(validation.IsDNS1123Subdomain(hostname)) != 0 {
		return nil, fmt.Errorf("untrusted hostname")
	}
	matches := 0
	for _, capacity := range server.Capacity {
		if capacity.Metro == endpoint.Spec.Metro && capacity.Assignment == endpoint.Spec.Assignment {
			matches++
		}
	}
	if matches != 1 {
		return nil, fmt.Errorf("untrusted placement")
	}
	if err := server.Driver.Applied(ctx, endpoint, true); err != nil {
		return nil, err
	}
	check := server.Check
	if check == nil {
		check = CheckPublicEndpoint
	}
	if err := check(ctx, hostname, endpoint.Spec.Assignment.Frontend, endpoint.Status.CertificateRevision); err != nil {
		return nil, err
	}
	current := &connect.ConnectEndpoint{}
	if err := server.Project.Get(ctx, key, current); err != nil {
		return nil, err
	}
	if current.UID != endpoint.UID || current.DeletionTimestamp != nil || !reflect.DeepEqual(current.Spec, endpoint.Spec) || current.Status.Revision != endpoint.Status.Revision || current.Status.CertificateRevision != endpoint.Status.CertificateRevision {
		return nil, fmt.Errorf("reservation changed during observation")
	}
	if err := server.Driver.Applied(ctx, current, true); err != nil {
		return nil, err
	}
	return &endpoints.ProbeReport{EndpointRef: endpoints.ProbeEndpointReference{Namespace: server.RuntimeNamespace, Name: name}, Hostname: hostname, Revision: current.Status.Revision, CertificateRevision: current.Status.CertificateRevision, Cell: current.Spec.Assignment.Cell, CheckedAt: time.Now().UTC(), HTTP2: true, HTTP3: true, DNS: true}, nil
}

func CheckPublicEndpoint(ctx context.Context, hostname, frontend, revision string) error {
	canonical, err := net.DefaultResolver.LookupCNAME(ctx, hostname)
	if err != nil {
		return err
	}
	expected, err := net.DefaultResolver.LookupCNAME(ctx, frontend)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSuffix(canonical, "."), strings.TrimSuffix(expected, ".")) {
		return fmt.Errorf("DNS frontend differs")
	}
	addresses, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("hostname has no address")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname, VerifyConnection: verifyRevision(revision)}
	return checkProtocols(ctx, hostname, tlsConfig)
}

func verifyRevision(revision string) func(tls.ConnectionState) error {
	return func(connection tls.ConnectionState) error {
		if len(connection.VerifiedChains) == 0 || len(connection.PeerCertificates) == 0 {
			return fmt.Errorf("unverified certificate")
		}
		digest := sha256.Sum256(connection.PeerCertificates[0].Raw)
		if hex.EncodeToString(digest[:]) != revision {
			return fmt.Errorf("certificate revision differs")
		}
		return nil
	}
}

func checkProtocols(ctx context.Context, authority string, tlsConfig *tls.Config) error {
	h2Transport := &http2.Transport{TLSClientConfig: tlsConfig.Clone()}
	defer h2Transport.CloseIdleConnections()
	h3Transport := &http3.Transport{TLSClientConfig: tlsConfig.Clone()}
	defer h3Transport.Close()
	for _, protocol := range []struct {
		transport     http.RoundTripper
		major, status int
	}{{h2Transport, 2, http.StatusBadRequest}, {h3Transport, 3, http.StatusMethodNotAllowed}} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+authority+"/.well-known/masque/ip/*/*/", nil)
		if err != nil {
			return err
		}
		response, err := protocol.transport.RoundTrip(request)
		if err != nil {
			return err
		}
		_ = response.Body.Close()
		if response.ProtoMajor != protocol.major || response.StatusCode != protocol.status {
			return fmt.Errorf("unexpected endpoint protocol response")
		}
	}
	return nil
}
