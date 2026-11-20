package endpoints

import (
	"context"
	"errors"
	"testing"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type driverFixture struct {
	certificate Certificate
	fail        string
	calls       []string
	removed     bool
}

func (fixture *driverFixture) call(name string) error {
	fixture.calls = append(fixture.calls, name)
	if fixture.fail == name {
		return errors.New("dependency unavailable")
	}
	return nil
}
func (fixture *driverFixture) Certificate(context.Context, *connect.ConnectEndpoint) (Certificate, error) {
	return fixture.certificate, fixture.call("certificate")
}
func (fixture *driverFixture) Apply(_ context.Context, _ *connect.ConnectEndpoint, enabled bool) error {
	if enabled {
		return fixture.call("apply")
	}
	return fixture.call("disable")
}
func (fixture *driverFixture) Applied(_ context.Context, _ *connect.ConnectEndpoint, enabled bool) error {
	if enabled {
		return fixture.call("applied")
	}
	return fixture.call("stopped")
}
func (fixture *driverFixture) Route(_ context.Context, _ *connect.ConnectEndpoint, enabled bool) error {
	if enabled {
		return fixture.call("route")
	}
	return fixture.call("withdraw")
}
func (fixture *driverFixture) Probe(context.Context, *connect.ConnectEndpoint) error {
	return fixture.call("probe")
}
func (fixture *driverFixture) Prune(context.Context, *connect.ConnectEndpoint) error {
	return fixture.call("prune")
}
func (fixture *driverFixture) RemoveDelivery(context.Context, *connect.ConnectEndpoint) (bool, error) {
	return fixture.removed, fixture.call("remove-delivery")
}
func (fixture *driverFixture) RemoveCertificate(context.Context, *connect.ConnectEndpoint) (bool, error) {
	return fixture.removed, fixture.call("remove-certificate")
}

func endpointFixture() *connect.ConnectEndpoint {
	return &connect.ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Namespace: "service", UID: "reservation-uid"}, Spec: connect.ConnectEndpointSpec{CustomerProjectUID: "customer-uid", GatewayUID: "gateway-uid", Metro: "dfw", Hostname: "endpoint.connect.example.test", CustomerProject: "customer", GatewayNamespace: "default", GatewayName: "gateway", NetworkUID: "network-uid", Lifecycle: "Active", Assignment: connect.EndpointAssignment{Cell: "cell-a", Provider: "shared", Frontend: "a.example.test", VPC: connect.EndpointVPCReference{Namespace: "vpc", Name: "network", UID: "vpc-uid"}}}}
}

func projectFixture(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := connect.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&connect.ConnectEndpoint{}, &connect.ConnectGrant{}).WithObjects(objects...).Build()
}

func TestReservationIdentityAndMetroCollapse(t *testing.T) {
	ctx := context.Background()
	project := projectFixture(t)
	spec := endpointFixture().Spec
	first, err := Reserve(ctx, project, "service", "connect.example.test", spec)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Reserve(ctx, project, "service", "connect.example.test", spec)
	if err != nil || first.Name != again.Name {
		t.Fatal("retry allocated different reservation", err)
	}
	spec.GatewayUID = "replacement"
	replacement, err := Reserve(ctx, project, "service", "connect.example.test", spec)
	if err != nil || replacement.Spec.Hostname == first.Spec.Hostname {
		t.Fatal("recreated gateway reused hostname", err)
	}
	spec.CustomerProjectUID = "other-tenant"
	other, err := Reserve(ctx, project, "service", "connect.example.test", spec)
	if err != nil || other.Name == replacement.Name {
		t.Fatal("tenant identity collision", err)
	}
	metros, err := Metros(map[string]string{"location-a": "dfw", "location-b": "dfw", "location-c": "iad"})
	if err != nil || len(metros) != 2 {
		t.Fatal(metros, err)
	}
	if _, err := Metros(map[string]string{"location-a": ""}); err == nil {
		t.Fatal("unknown metro accepted")
	}
	first.Spec.Lifecycle = "Deleting"
	if err := project.Update(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(ctx, project, "service", "connect.example.test", first.Spec); err == nil {
		t.Fatal("retired reservation reactivated")
	}
}

func TestReadinessRotationAndFailureGates(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	endpoint := endpointFixture()
	project := projectFixture(t, endpoint)
	driver := &driverFixture{certificate: Certificate{Revision: "first", NotAfter: now.Add(24 * time.Hour)}}
	reconciler := &Reconciler{Project: project, Driver: driver, Now: func() time.Time { return now }, ExpiryMargin: 5 * time.Minute, DNSDrain: time.Minute}
	key := client.ObjectKeyFromObject(endpoint)
	for range 3 {
		if err := reconciler.Reconcile(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if !Ready(endpoint, now, 5*time.Minute) {
		t.Fatal("endpoint never became ready")
	}
	for _, gate := range []string{"certificate", "apply", "applied", "route", "probe", "prune"} {
		driver.fail = gate
		if err := reconciler.Reconcile(ctx, key); err == nil {
			t.Fatalf("%s failure ignored", gate)
		}
		if err := project.Get(ctx, key, endpoint); err != nil {
			t.Fatal(err)
		}
		if Ready(endpoint, now, 5*time.Minute) {
			t.Fatalf("%s failure remained ready", gate)
		}
	}
	driver.fail = ""
	driver.certificate = Certificate{Revision: "emergency-shorter", NotAfter: now.Add(time.Hour)}
	if err := reconciler.Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.Status.Revision != 2 || endpoint.Status.Ready {
		t.Fatal("rekey failed to fence readiness", endpoint.Status)
	}
	if err := reconciler.Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if !Ready(endpoint, now, 5*time.Minute) {
		t.Fatal("shorter rekey not accepted")
	}
	now = now.Add(56 * time.Minute)
	driver.fail = "certificate"
	driver.calls = nil
	if err := reconciler.Reconcile(ctx, key); err == nil {
		t.Fatal("failed issuance should block")
	}
	if len(driver.calls) == 0 || driver.calls[0] != "withdraw" {
		t.Fatal("failed renewal prevented expiring DNS withdrawal", driver.calls)
	}
}

func TestCleanupWaitsForForwardingAndEveryRemoval(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	endpoint := endpointFixture()
	endpoint.Spec.Lifecycle = "Deleting"
	endpoint.Status.Revision = 7
	project := projectFixture(t, endpoint)
	driver := &driverFixture{fail: "stopped"}
	reconciler := &Reconciler{Project: project, Driver: driver, Now: func() time.Time { return now }, DNSDrain: time.Minute}
	key := client.ObjectKeyFromObject(endpoint)
	if err := reconciler.Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(ctx, key); err == nil {
		t.Fatal("missing forwarding ack ignored")
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.Status.CleanupStep != "Disable" || endpoint.Status.Revision != 8 {
		t.Fatal(endpoint.Status)
	}
	driver.fail = ""
	for range 3 {
		if err := reconciler.Reconcile(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.Status.CleanupStep != "Drain" {
		t.Fatal("cached DNS drain skipped", endpoint.Status)
	}
	now = now.Add(2 * time.Minute)
	for range 2 {
		if err := reconciler.Reconcile(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.Status.CleanupStep != "Delivery" {
		t.Fatal("lost cell did not retain cleanup", endpoint.Status)
	}
	driver.removed = true
	for range 3 {
		if err := reconciler.Reconcile(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.Spec.Lifecycle != "Retired" {
		t.Fatal("hostname tombstone missing", endpoint.Spec)
	}
}
