package endpoints

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeRequiresCurrentCompleteExternalEvidence(t *testing.T) {
	now := time.Now()
	endpoint := endpointFixture()
	endpoint.Status.Revision = 4
	endpoint.Status.CertificateRevision = "leaf-revision"
	valid := ProbeReport{EndpointRef: ProbeEndpointReference{Namespace: "masque", Name: endpoint.Name}, Hostname: endpoint.Spec.Hostname, Revision: 4, CertificateRevision: "leaf-revision", Cell: "cell-a", CheckedAt: now, HTTP3: true, HTTP2: true, DNS: true}
	report := valid
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/endpoints/masque/"+endpoint.Name {
			t.Error("probe targeted wrong endpoint")
		}
		_ = json.NewEncoder(writer).Encode(report)
	}))
	defer server.Close()
	probe, err := HTTPProbe(server.URL+"/endpoints", "masque", server.Client(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := probe(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ProbeReport){
		"stale":       func(value *ProbeReport) { value.CheckedAt = now.Add(-11 * time.Second) },
		"future":      func(value *ProbeReport) { value.CheckedAt = now.Add(time.Second) },
		"revision":    func(value *ProbeReport) { value.Revision-- },
		"certificate": func(value *ProbeReport) { value.CertificateRevision = "old" },
		"cell":        func(value *ProbeReport) { value.Cell = "other" },
		"identity":    func(value *ProbeReport) { value.EndpointRef.Name = "other" },
		"namespace":   func(value *ProbeReport) { value.EndpointRef.Namespace = "other" },
		"hostname":    func(value *ProbeReport) { value.Hostname = "other.example.test" },
		"h3":          func(value *ProbeReport) { value.HTTP3 = false },
		"h2":          func(value *ProbeReport) { value.HTTP2 = false },
		"dns":         func(value *ProbeReport) { value.DNS = false },
	} {
		t.Run(name, func(t *testing.T) {
			report = valid
			mutate(&report)
			if err := probe(context.Background(), endpoint); err == nil {
				t.Fatal("incomplete evidence accepted")
			}
		})
	}
	if _, err := HTTPProbe("http://untrusted.example.test", "masque", server.Client(), time.Now); err == nil {
		t.Fatal("plaintext probe accepted")
	}
}
