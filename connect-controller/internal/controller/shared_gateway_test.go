package controller

import (
	"context"
	"testing"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	"go.datum.net/connect-controller/internal/endpoints"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSharedGatewayBindingsPinIndependentNetworkIdentities(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	verified, expires := metav1.NewTime(now), metav1.NewTime(now.Add(time.Hour))
	scheme := runtime.NewScheme()
	_ = connect.AddToScheme(scheme)
	project := &unstructured.Unstructured{}
	project.SetGroupVersionKind(schema.GroupVersionKind{Group: "resourcemanager.miloapis.com", Version: "v1alpha1", Kind: "Project"})
	project.SetName("customer")
	project.SetUID("project-uid")
	gateway := &connect.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "default", UID: "gateway-uid"}, Spec: connect.ConnectGatewaySpec{ContractVersion: managedGatewayContract}}
	connector := &connect.Connector{ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "default", UID: "connector-uid", Labels: map[string]string{"policy.connect.datum.net/team": "one"}}, Status: connect.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready"}}}}
	policy := &connect.ConnectConnectionPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow", Namespace: "default", Generation: 1}, Spec: connect.ConnectConnectionPolicySpec{GatewayRef: &connect.LocalObjectReference{Name: "shared"}, NetworkRefs: []connect.LocalObjectReference{{Name: "one"}, {Name: "two"}}, ConnectorSelector: metav1.LabelSelector{MatchLabels: connector.Labels}, Access: connect.ConnectPolicyAccess{Permission: "Network"}}}
	endpoint := &connect.ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Namespace: "service", UID: "endpoint-uid"}, Spec: connect.ConnectEndpointSpec{CustomerProjectUID: "project-uid", GatewayUID: "gateway-uid", GatewayNamespace: "default", Lifecycle: "Active", Hostname: "opaque.example.test", Assignment: connect.EndpointAssignment{Cell: "cell"}}, Status: connect.ConnectEndpointStatus{Phase: "Active", Revision: 1, CertificateRevision: "certificate", Ready: true, NotAfter: &expires, VerifiedAt: &verified}}
	placement := &connect.ConnectGatewayPlacement{ObjectMeta: metav1.ObjectMeta{Name: "shared-dfw", Namespace: "default"}, Spec: connect.ConnectGatewayPlacementSpec{GatewayRef: "shared"}, Status: connect.ConnectGatewayPlacementStatus{AssignmentRef: "endpoint"}}
	objects := []client.Object{gateway, connector, policy, placement}
	networks := map[string]*unstructured.Unstructured{}
	for _, name := range []string{"one", "two", "denied"} {
		network := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "networking.datumapis.com/v1alpha", "kind": "Network", "metadata": map[string]interface{}{"name": name, "namespace": "default", "uid": name + "-uid"}, "status": map[string]interface{}{"ipam": map[string]interface{}{"ipv6Prefix": "fd00::/48"}}}}
		networks[name] = network
		binding := &connect.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID(name + "-binding")}, Spec: connect.ConnectNetworkBindingSpec{GatewayRef: "shared", ConnectorRef: "laptop", NetworkRef: name}, Status: connect.ConnectNetworkBindingStatus{SelectedPlacementRef: placement.Name}}
		objects = append(objects, network, binding)
	}
	customer := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	durable := fake.NewClientBuilder().WithScheme(scheme).WithObjects(endpoint).Build()
	service := &endpoints.Service{Root: fake.NewClientBuilder().WithScheme(scheme).WithObjects(project).Build(), Namespace: "service", Reconciler: &endpoints.Reconciler{Project: durable}}
	for _, name := range []string{"one", "two"} {
		service.Reachability = append(service.Reachability, endpoints.Reachability{NetworkUID: name + "-uid", Cell: "cell", VPC: connect.EndpointVPCReference{Namespace: "vpcs", Name: name, UID: name + "-vpc"}})
	}
	resolver := ManagedBindingResolver{Customer: customer, Service: service, ProjectName: "customer", Namespace: "default", Now: func() time.Time { return now }}
	first, err := resolver.Resolve(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.Resolve(ctx, "two")
	if err != nil {
		t.Fatal(err)
	}
	if first.Endpoint.UID != second.Endpoint.UID || first.VPC == second.VPC || first.PolicyRevision == second.PolicyRevision {
		t.Fatal("binding scopes were collapsed")
	}
	if _, err := resolver.Resolve(ctx, "denied"); err == nil {
		t.Fatal("gateway authorization broadened network access")
	}
	receipt := &connect.ConnectGrant{ObjectMeta: metav1.ObjectMeta{Name: "receipt", Namespace: "service"}, Spec: connect.ConnectGrantSpec{EndpointName: endpoint.Name, EndpointUID: string(endpoint.UID), BindingName: first.Name, BindingUID: first.UID, NetworkName: first.NetworkName, NetworkUID: first.NetworkUID, VPC: first.VPC, Cell: "cell", PolicyRevision: first.PolicyRevision}}
	if err := durable.Create(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if valid, err := GrantStillAuthorized(ctx, customer, endpoint, receipt); err != nil || !valid {
		t.Fatal("valid grant rejected", err)
	}
	service.Reachability[0].VPC.UID = "replacement-vpc"
	if _, err := resolver.Resolve(ctx, "one"); err == nil {
		t.Fatal("recreated VPC silently rebound old binding")
	}
	if _, err := resolver.Resolve(ctx, "two"); err != nil {
		t.Fatal("VPC replacement revoked sibling", err)
	}
	service.Reachability[0].VPC = first.VPC
	if err := customer.Delete(ctx, networks["one"]); err != nil {
		t.Fatal(err)
	}
	if valid, err := GrantStillAuthorized(ctx, customer, endpoint, receipt); err != nil || valid {
		t.Fatal("deleted network retained grant", err)
	}
	if _, err := resolver.Resolve(ctx, "two"); err != nil {
		t.Fatal("sibling revoked", err)
	}
	replacement := networks["one"].DeepCopy()
	replacement.SetResourceVersion("")
	replacement.SetUID("replacement-uid")
	if err := customer.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	service.Reachability = append(service.Reachability, endpoints.Reachability{NetworkUID: "replacement-uid", Cell: "cell", VPC: first.VPC})
	if _, err := resolver.Resolve(ctx, "one"); err == nil {
		t.Fatal("recreated network silently rebound old binding")
	}
	if valid, err := GrantStillAuthorized(ctx, customer, endpoint, receipt); err != nil || valid {
		t.Fatal("recreated network retained old grant", err)
	}
	if err := durable.Get(ctx, client.ObjectKeyFromObject(endpoint), endpoint); err != nil || !endpoint.Status.Ready || endpoint.Spec.Lifecycle != "Active" {
		t.Fatal("binding deletion changed shared endpoint", err)
	}
	policy.Spec.NetworkRefs = nil
	if err := customer.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(ctx, "two"); err == nil {
		t.Fatal("legacy unscoped policy broadened")
	}
}
