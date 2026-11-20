package endpoints

import (
	"context"
	"errors"
	"testing"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type unavailableReader struct{ client.Client }

func (reader unavailableReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("temporary API failure")
}

func TestServiceMetroCollapseAndDurableOwnership(t *testing.T) {
	ctx := context.Background()
	endpoint := endpointFixture()
	project := object(schema.GroupVersionKind{Group: "resourcemanager.miloapis.com", Version: "v1alpha1", Kind: "Project"}, "", endpoint.Spec.CustomerProject)
	project.SetUID("customer-uid")
	root := resourceClient(t, project)
	network := object(schema.GroupVersionKind{Group: "networking.datumapis.com", Version: "v1alpha", Kind: "Network"}, "default", "network")
	network.SetUID("network-uid")
	gateway := &connect.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gateway", UID: "gateway-uid"}, Spec: connect.ConnectGatewaySpec{NetworkRef: "network"}}
	customer := resourceClient(t, gateway, network)
	serviceProject := resourceClient(t)
	service := &Service{Root: root, Namespace: "service", Domain: "connect.example.test", Provision: true, Reconciler: &Reconciler{Project: serviceProject}, Customer: func(context.Context, string) (client.Client, error) { return customer, nil }, Capacity: []Capacity{{Metro: "dfw", NetworkUID: "network-uid", Assignment: endpoint.Spec.Assignment}}}
	for range 2 {
		if err := service.Sync(ctx, customer, "customer", gateway, map[string]string{"location-a": "dfw", "location-b": "dfw"}); err != nil {
			t.Fatal(err)
		}
	}
	var reservations connect.ConnectEndpointList
	if err := serviceProject.List(ctx, &reservations); err != nil || len(reservations.Items) != 1 {
		t.Fatal("Locations did not collapse", err)
	}
	reserved := &reservations.Items[0]
	if reserved.Spec.Assignment.Cell != "cell-a" || len(reserved.OwnerReferences) != 0 {
		t.Fatal("assignment or durable ownership incorrect")
	}
	service.Root = unavailableReader{root}
	if gone, err := service.ownerGone(ctx, reserved); gone || err == nil {
		t.Fatal("outage treated as deletion")
	}
	driver := &driverFixture{fail: "certificate"}
	service.Reconciler.Driver = driver
	service.Reconciler.Now = time.Now
	reserved.Status.Phase = "Active"
	if err := serviceProject.Status().Update(ctx, reserved); err != nil {
		t.Fatal(err)
	}
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(driver.calls) != 1 || driver.calls[0] != "certificate" {
		t.Fatal("customer API outage blocked independent renewal")
	}
	service.Root = root
	if gone, err := service.ownerGone(ctx, reserved); gone || err != nil {
		t.Fatal("live owner missing", err)
	}
	if err := root.Delete(ctx, project); err != nil {
		t.Fatal(err)
	}
	if gone, err := service.ownerGone(ctx, reserved); !gone || err != nil {
		t.Fatal("deleted project not detected", err)
	}
	if err := serviceProject.Get(ctx, client.ObjectKeyFromObject(reserved), reserved); err != nil {
		t.Fatal("reservation disappeared with customer", err)
	}
}

func TestRetiredEndpointReactivationStartsNewCredentialEpoch(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	endpoint := endpointFixture()
	endpoint.Status = connect.ConnectEndpointStatus{Phase: "Retired", Revision: 8, ActivationRevision: 1, CleanupStep: "Retired", CertificateRef: connect.EndpointCertificateReference{Name: endpoint.Name, UID: "old-cert"}}
	project := projectFixture(t, endpoint)
	reconciler := &Reconciler{Project: project, Driver: &driverFixture{certificate: Certificate{Revision: "new-cert", NotAfter: now.Add(time.Hour)}}, Now: func() time.Time { return now }, ExpiryMargin: time.Minute}
	key := client.ObjectKeyFromObject(endpoint)
	if err := reconciler.Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.Status.ActivationRevision != 9 || endpoint.Status.CertificateRef.UID != "" || endpoint.Status.Ready || endpoint.Status.CleanupStep != "" {
		t.Fatal("old authorization leaked into reactivation", endpoint.Status)
	}
	if err := reconciler.Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := project.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.Status.Revision != 9 || endpoint.Spec.Assignment.Cell != "cell-a" {
		t.Fatal("reactivation lost fence or selected cell")
	}
}
