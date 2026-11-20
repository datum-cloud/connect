package endpointprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	"go.datum.net/connect-controller/internal/endpoints"
	coordination "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fixture(t *testing.T) (*Server, *connect.ConnectEndpoint) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	scheme := runtime.NewScheme()
	if err := connect.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := coordination.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	endpoint := &connect.ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "reservation", Namespace: "default", UID: "reservation-uid"}, Spec: connect.ConnectEndpointSpec{Lifecycle: "Active", Hostname: "opaque.connect.example.test", Metro: "central", Assignment: connect.EndpointAssignment{Cell: "selected", Provider: "masque", Frontend: "frontend.example.test"}}, Status: connect.ConnectEndpointStatus{Revision: 4, CertificateRevision: "digest"}}
	registration := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "galactic.datumapis.com/v1alpha1", "kind": "MASQUEEndpoint", "metadata": map[string]any{"name": endpoint.Name, "namespace": "masque-system"}, "spec": map[string]any{"hostname": endpoint.Spec.Hostname, "provider": "masque", "revision": int64(4), "enabled": true, "certificateRef": map[string]any{"name": endpoints.SecretName(endpoint), "revision": "digest"}}, "status": map[string]any{"instances": []any{map[string]any{"instanceName": "ei-pod", "observedRevision": int64(4), "appliedRevision": int64(4), "appliedCertificateRevision": "digest", "state": "Applied", "lastHeartbeatTime": now.Format(time.RFC3339)}}}}}
	instance := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "galactic.datumapis.com/v1alpha1", "kind": "EdgeInstance", "metadata": map[string]any{"name": "ei-pod", "namespace": "masque-system", "uid": "instance", "creationTimestamp": now.Add(-time.Minute).Format(time.RFC3339)}, "spec": map[string]any{"providerRef": map[string]any{"name": "masque"}, "podUID": "pod"}}}
	holder, duration := "holder", int32(30)
	lease := &coordination.Lease{ObjectMeta: metav1.ObjectMeta{Name: "ei-pod", Namespace: "masque-system", UID: "lease", OwnerReferences: []metav1.OwnerReference{{Kind: "EdgeInstance", UID: "instance"}}, Annotations: map[string]string{"galactic.datumapis.com/edge-pod-uid": "pod"}}, Spec: coordination.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, AcquireTime: &metav1.MicroTime{Time: now.Add(-time.Minute)}, RenewTime: &metav1.MicroTime{Time: now}}}
	scheme.AddKnownTypeWithName(schema.GroupVersionKind{Group: "galactic.datumapis.com", Version: "v1alpha1", Kind: "EdgeInstanceList"}, &unstructured.UnstructuredList{})
	cell := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(registration, instance, lease).Build()
	project := fake.NewClientBuilder().WithScheme(scheme).WithObjects(endpoint).Build()
	return &Server{Project: project, Namespace: "default", RuntimeNamespace: "masque-system", Domain: "connect.example.test", Capacity: []endpoints.Capacity{{Metro: "central", Assignment: endpoint.Spec.Assignment}}, Driver: &endpoints.KubernetesDriver{RuntimeNamespace: "masque-system", Cells: map[string]client.Client{"selected": cell}, Now: func() time.Time { return now }}, Check: func(context.Context, string, string, string) error { return nil }}, endpoint
}

func TestProbeOnlyReportsVerifiedSelectedEndpoint(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-api", "missing-api", "wrong-capacity", "wrong-domain", "network-failure", "revoked-during-check", "certificate-changed", "membership-disappeared"} {
		t.Run(scenario, func(t *testing.T) {
			server, endpoint := fixture(t)
			switch scenario {
			case "wrong-api", "missing-api":
				server.Driver.Cells["other"] = server.Driver.Cells["selected"]
				delete(server.Driver.Cells, "selected")
				if scenario == "wrong-api" {
					server.Driver.Cells["selected"] = fake.NewClientBuilder().Build()
				}
			case "wrong-capacity":
				server.Capacity[0].Assignment.Cell = "other"
			case "wrong-domain":
				server.Domain = "evil.example.test"
			case "network-failure":
				server.Check = func(context.Context, string, string, string) error { return fmt.Errorf("unreachable") }
			case "revoked-during-check", "certificate-changed", "membership-disappeared":
				server.Check = func(ctx context.Context, _, _, _ string) error {
					if scenario == "membership-disappeared" {
						delete(server.Driver.Cells, "selected")
						return nil
					}
					current := &connect.ConnectEndpoint{}
					if err := server.Project.Get(ctx, client.ObjectKeyFromObject(endpoint), current); err != nil {
						return err
					}
					if scenario == "revoked-during-check" {
						current.Spec.Lifecycle = "Deleting"
					} else {
						current.Status.CertificateRevision = "new"
					}
					return server.Project.(client.Client).Update(ctx, current)
				}
			}
			writer := httptest.NewRecorder()
			server.Handler().ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/endpoints/masque-system/reservation", nil))
			if scenario == "valid" && writer.Code != http.StatusOK {
				t.Fatalf("valid probe failed: %s", writer.Body.String())
			}
			if scenario != "valid" && writer.Code == http.StatusOK {
				t.Fatal("unverified probe passed")
			}
			if writer.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("response may be cached")
			}
		})
	}
}

func TestProbeClientRequiresExplicitTrust(t *testing.T) {
	for _, paths := range [][3]string{{}, {"missing", "missing", "missing"}} {
		if _, err := ClientTLS(paths[0], paths[1], paths[2]); err == nil {
			t.Fatal("missing trust accepted")
		}
	}
}

func TestProbeMutualTLSRejectsUnauthenticatedClient(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe-test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := ClientTLS(certFile, certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: config.Certificates, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: config.RootCAs}
	server.StartTLS()
	defer server.Close()
	for _, authenticated := range []bool{false, true} {
		clientConfig := config.Clone()
		if !authenticated {
			clientConfig.Certificates = nil
		}
		transport := &http.Transport{TLSClientConfig: clientConfig}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(server.URL)
		if !authenticated && err == nil {
			response.Body.Close()
			t.Fatal("unauthenticated client accepted")
		}
		if authenticated {
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatal("authenticated client rejected")
			}
		}
	}
}

func TestRealTLSHTTP2AndQUICRequireExactCertificateAndResponses(t *testing.T) {
	for _, scenario := range []string{"valid", "disabled", "wrong-certificate", "untrusted-certificate", "wrong-h3-response"} {
		t.Run(scenario, func(t *testing.T) {
			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/.well-known/masque/ip/*/*/" || request.Method != http.MethodGet {
					t.Error("unexpected request")
				}
				status := http.StatusBadRequest
				if request.ProtoMajor == 3 {
					status = http.StatusMethodNotAllowed
				}
				if scenario == "disabled" {
					status = http.StatusMisdirectedRequest
				}
				if scenario == "wrong-h3-response" && request.ProtoMajor == 3 {
					status = http.StatusOK
				}
				writer.WriteHeader(status)
			})
			tcp := httptest.NewUnstartedServer(handler)
			tcp.EnableHTTP2 = true
			tcp.StartTLS()
			defer tcp.Close()
			udp, err := net.ListenPacket("udp", tcp.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			quic := &http3.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: tcp.TLS.Certificates, MinVersion: tls.VersionTLS13}}
			defer quic.Close()
			defer udp.Close()
			go func() { _ = quic.Serve(udp) }()
			digest := sha256.Sum256(tcp.Certificate().Raw)
			revision := hex.EncodeToString(digest[:])
			if scenario == "wrong-certificate" {
				revision = "other"
			}
			config := tcp.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			config.VerifyConnection = verifyRevision(revision)
			if scenario == "untrusted-certificate" {
				config.RootCAs = nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = checkProtocols(ctx, tcp.Listener.Addr().String(), config)
			if scenario == "valid" && err != nil {
				t.Fatal(err)
			}
			if scenario != "valid" && err == nil {
				t.Fatal("invalid public protocol observation accepted")
			}
		})
	}
}
