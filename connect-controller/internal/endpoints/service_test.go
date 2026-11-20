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

func TestReachabilityFailsClosed(t *testing.T) {
	vpc := connect.EndpointVPCReference{Namespace: "vpcs", Name: "one", UID: "vpc-uid"}
	mapping := Reachability{NetworkUID: "network", Cell: "cell", VPC: vpc}
	for name, mappings := range map[string][]Reachability{
		"missing":       nil,
		"other cell":    {{NetworkUID: "network", Cell: "other", VPC: vpc}},
		"other network": {{NetworkUID: "other", Cell: "cell", VPC: vpc}},
		"ambiguous":     {mapping, mapping},
		"incomplete":    {{NetworkUID: "network", Cell: "cell", VPC: connect.EndpointVPCReference{UID: "uid"}}},
	} {
		t.Run(name, func(t *testing.T) {
			service := &Service{Reachability: mappings}
			if _, err := service.ResolveVPC("network", "cell"); err == nil {
				t.Fatal("invalid reachability accepted")
			}
		})
	}
	service := &Service{Reachability: []Reachability{mapping}}
	if actual, err := service.ResolveVPC("network", "cell"); err != nil || actual != vpc {
		t.Fatal("valid reachability rejected", err)
	}
}

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
	placement := &connect.ConnectGatewayPlacement{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "placement", Labels: map[string]string{"connect.datum.net/gateway": "gateway"}}, Spec: connect.ConnectGatewayPlacementSpec{GatewayRef: "gateway", LocationRef: "location-a"}, Status: connect.ConnectGatewayPlacementStatus{AssignmentRef: "private-reservation"}}
	customer := resourceClient(t, gateway, network, placement)
	serviceProject := resourceClient(t)
	service := &Service{Root: root, Namespace: "service", Domain: "connect.example.test", Provision: true, Reconciler: &Reconciler{Project: serviceProject, Now: time.Now}, Customer: func(context.Context, string) (client.Client, error) { return customer, nil }, Capacity: []Capacity{{Metro: "dfw", Assignment: endpoint.Spec.Assignment}}}
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
	if err := customer.Get(ctx, client.ObjectKeyFromObject(placement), placement); err != nil || placement.Status.AssignmentRef != "" || placement.Status.Hostname != reserved.Spec.Hostname {
		t.Fatal("managed placement leaked service reservation or lost public hostname", err)
	}
	if reserved.Spec.Hostname == reserved.Name+".connect.example.test" {
		t.Fatal("public hostname exposes UID-derived reservation")
	}
	if err := customer.Delete(ctx, network); err != nil {
		t.Fatal(err)
	}
	if err := service.Sync(ctx, customer, "customer", gateway, map[string]string{"location-a": "dfw"}); err != nil {
		t.Fatal("network deletion affected shared endpoint", err)
	}
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
	reserved.Status.CertificateRef.Name = reserved.Name
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
	endpoint.Status.DeliveryReceipts = []connect.EndpointDeliveryReceipt{{State: "Removed", APIVersion: "v1", Kind: "Secret", Namespace: "masque", Name: "old-secret", UID: "old-uid", ContentDigest: "old-digest"}}
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
	if len(endpoint.Status.DeliveryReceipts) != 1 || endpoint.Status.DeliveryReceipts[0].State != "Removed" || endpoint.Status.DeliveryReceipts[0].UID != "old-uid" {
		t.Fatal("reactivation erased cleanup history")
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
