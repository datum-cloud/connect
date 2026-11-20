package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	cloud "go.datum.net/galactic/api/cloud/v1alpha1"
	galactic "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/pkg/masquegrant"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRealGalacticGrantLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	verified, expires := metav1.NewTime(now), metav1.NewTime(now.Add(time.Hour))
	scheme := runtime.NewScheme()
	for _, install := range []func(*runtime.Scheme) error{connect.AddToScheme, cloud.AddToScheme, galactic.AddToScheme, corev1.AddToScheme} {
		if err := install(scheme); err != nil {
			t.Fatal(err)
		}
	}
	vpc := &cloud.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "vpc", UID: "11111111-1111-1111-1111-111111111111"}, Spec: cloud.VPCSpec{Networks: []cloud.Network{"fd20:a1b:2c3d::/48"}}}
	ref := masquegrant.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name, UID: string(vpc.UID)}
	registration := &galactic.MASQUEEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Namespace: "masque-system"}, Spec: galactic.MASQUEEndpointSpec{MASQUEEndpointScope: galactic.MASQUEEndpointScope{EndpointUID: "endpoint-uid", CustomerProjectUID: "project-uid", GatewayUID: "gateway-uid", Cell: "cell-a", Hostname: "gateway.example.test"}, Metro: "dfw", Provider: "shared", Revision: 1, Enabled: true, CertificateRef: galactic.MASQUEEndpointCertificateReference{Name: "tls", Revision: strings.Repeat("a", 64)}}}
	cell := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, registration).Build()
	endpoint := &connect.ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Namespace: "service", UID: "endpoint-uid"}, Spec: connect.ConnectEndpointSpec{Lifecycle: "Active", Hostname: registration.Spec.Hostname, CustomerProjectUID: "project-uid", GatewayUID: "gateway-uid", Assignment: connect.EndpointAssignment{Cell: "cell-a"}}, Status: connect.ConnectEndpointStatus{Ready: true, Phase: "Active", Revision: 1, CertificateRevision: registration.Spec.CertificateRef.Revision, NotAfter: &expires, VerifiedAt: &verified}}
	project := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&connect.ConnectEndpoint{}, &connect.ConnectGrant{}).WithObjects(endpoint).Build()
	issuer := &ManagedIssuer{Project: project, Namespace: "service", Authorities: map[string]GrantAPI{"cell-a": masquegrant.New(cell, "masque-system")}, Now: func() time.Time { return now }}
	binding := Binding{NetworkName: "network", NetworkUID: "network-uid", VPC: connect.EndpointVPCReference(ref), Name: "binding", UID: "binding-uid", PolicyRevision: "policy-1", Endpoint: endpoint, NetworkPlan: NetworkPlan{DestinationPrefixes: []string{"fd20:a1b:2c3d::/48"}, MTU: 1280}}
	if _, err := issuer.Mint(ctx, binding); err == nil {
		t.Fatal("missing operator ledger/fence accepted")
	}
	ledgers := masquegrant.NewLedgers(cell, "masque-system")
	if err := ledgers.Init(ctx, ref, "cell-a", netip.MustParsePrefix("fd20:a1b:2c3d:10:1::/80"), netip.MustParsePrefix("fd20:a1b:2c3d:10:2::/80")); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Mint(ctx, binding); err == nil {
		t.Fatal("unaccepted registration issued credential")
	}
	encoded, err := json.Marshal(map[string]interface{}{"spec": registration.Spec, "removed": false, "revokedRevision": 0})
	if err != nil {
		t.Fatal(err)
	}
	fence := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("masque-endpoint-%x", sha256.Sum256([]byte(endpoint.UID))), Namespace: "masque-system"}, Data: map[string]string{"fence.json": string(encoded)}}
	if err := cell.Create(ctx, fence); err != nil {
		t.Fatal(err)
	}
	first, err := issuer.Mint(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	second, err := issuer.Mint(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	if first.ExpectedPrefix != second.ExpectedPrefix || first.Credential == second.Credential {
		t.Fatal("retry failed to rotate while retaining /96")
	}
	var receipts connect.ConnectGrantList
	if err := project.List(ctx, &receipts); err != nil || len(receipts.Items) != 1 {
		t.Fatal("durable receipt missing", err)
	}
	if err := issuer.Retire(ctx, &receipts.Items[0]); err != nil {
		t.Fatal(err)
	}
	ledger, _, err := ledgers.Read(ctx, ref.UID, "cell-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Entries) != 1 || !ledger.Entries[0].Retired || ledger.Entries[0].Prefix.String() != first.ExpectedPrefix {
		t.Fatal("allocation tombstone lost")
	}
	if _, err := issuer.Mint(ctx, binding); err == nil {
		t.Fatal("retired receipt resurrected")
	}
	var secrets corev1.SecretList
	if err := project.List(ctx, &secrets); err != nil || len(secrets.Items) != 0 {
		t.Fatal("credentials leaked into service Project", err)
	}
}

type authorityFixture struct {
	requests  []masquegrant.CreateRequest
	rotations int
	retired   int
	issued    masquegrant.Issued
	project   client.Client
}

func (fixture *authorityFixture) Create(ctx context.Context, request masquegrant.CreateRequest) (masquegrant.Issued, error) {
	var receipts connect.ConnectGrantList
	if err := fixture.project.List(ctx, &receipts); err != nil || len(receipts.Items) == 0 {
		panic("grant issued before durable receipt")
	}
	fixture.requests = append(fixture.requests, request)
	if len(fixture.requests) > 1 {
		return masquegrant.Issued{}, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, request.Connector)
	}
	fixture.issued.Connector = request.Connector
	fixture.issued.VPC = request.VPC.Selector()
	return fixture.issued, nil
}
func (fixture *authorityFixture) Rotate(context.Context, string, time.Duration) (masquegrant.Issued, error) {
	fixture.rotations++
	return fixture.issued, nil
}
func (fixture *authorityFixture) Retire(context.Context, string) error { fixture.retired++; return nil }

func TestManagedGrantRetryRetainsCellScopeAndPrefix(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	verified := metav1.NewTime(now)
	expires := metav1.NewTime(now.Add(time.Hour))
	endpoint := &connect.ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Namespace: "service", UID: "endpoint-uid"}, Spec: connect.ConnectEndpointSpec{Lifecycle: "Active", Hostname: "endpoint.example.test", CustomerProjectUID: "project-uid", GatewayUID: "gateway-uid", Assignment: connect.EndpointAssignment{Cell: "selected"}}, Status: connect.ConnectEndpointStatus{Ready: true, Phase: "Active", Revision: 1, CertificateRevision: "cert", NotAfter: &expires, VerifiedAt: &verified}}
	scheme := runtime.NewScheme()
	_ = connect.AddToScheme(scheme)
	project := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&connect.ConnectGrant{}, &connect.ConnectEndpoint{}).WithObjects(endpoint).Build()
	selected := &authorityFixture{project: project, issued: masquegrant.Issued{Credential: "opaque", Prefix: netip.MustParsePrefix("fd00:0:0:1::/96"), Expires: now.Add(5 * time.Minute)}}
	other := &authorityFixture{project: project}
	issuer := &ManagedIssuer{Project: project, Namespace: "service", Authorities: map[string]GrantAPI{"selected": selected, "other": other}, Now: func() time.Time { return now }}
	binding := Binding{NetworkName: "network", NetworkUID: "network-uid", VPC: connect.EndpointVPCReference{Namespace: "vpc", Name: "network", UID: "vpc-uid"}, Name: "binding", UID: "binding-uid", PolicyRevision: "policy-1", Endpoint: endpoint, NetworkPlan: NetworkPlan{DestinationPrefixes: []string{"fd00::/48"}, MTU: 1280}}
	first, err := issuer.Mint(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	again, err := issuer.Mint(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(other.requests) != 0 || selected.rotations != 1 || selected.requests[0].Connector != selected.requests[1].Connector || first.ExpectedPrefix != again.ExpectedPrefix {
		t.Fatal("retry drifted allocation/cell")
	}
	scope := selected.requests[0].Endpoint
	if scope.EndpointUID != "endpoint-uid" || scope.CustomerProjectUID != "project-uid" || selected.requests[0].NetworkUID != "network-uid" || selected.requests[0].BindingUID != "binding-uid" || scope.Cell != "selected" || scope.Hostname != endpoint.Spec.Hostname {
		t.Fatal("incomplete admission scope", scope)
	}
	var receipts connect.ConnectGrantList
	if err := project.List(ctx, &receipts); err != nil {
		t.Fatal(err)
	}
	if len(receipts.Items) != 1 {
		t.Fatal("duplicate durable grants")
	}
	if err := issuer.Retire(ctx, &receipts.Items[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Mint(ctx, binding); err == nil {
		t.Fatal("retired grant resurrected")
	}
	endpoint.Spec.Lifecycle = "Deleting"
	if err := project.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	binding.PolicyRevision = "new-policy"
	if _, err := issuer.Mint(ctx, binding); err == nil {
		t.Fatal("deleting endpoint issued grant")
	}
}
