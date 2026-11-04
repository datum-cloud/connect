package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
)

func policySelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{"policy.connect.datum.net/environment": "staging"},
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "policy.connect.datum.net/access-domain", Operator: metav1.LabelSelectorOpIn, Values: []string{"application", "observability"}},
			{Key: "policy.connect.datum.net/developer-access", Operator: metav1.LabelSelectorOpExists},
		},
	}
}

func TestPolicySelectorSupportsInAndExists(t *testing.T) {
	policy := &connectv1alpha1.ConnectConnectionPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "project"}, Spec: connectv1alpha1.ConnectConnectionPolicySpec{
		GatewaySelector: policySelector(), ConnectorSelector: *policySelector(), Access: connectv1alpha1.ConnectPolicyAccess{Permission: "Network"},
	}}
	gateways := []connectv1alpha1.ConnectGateway{
		{ObjectMeta: metav1.ObjectMeta{Name: "production", Namespace: "project", Labels: map[string]string{"policy.connect.datum.net/environment": "staging", "policy.connect.datum.net/access-domain": "application", "policy.connect.datum.net/developer-access": "true"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "wrong", Namespace: "project", Labels: map[string]string{"policy.connect.datum.net/environment": "staging", "policy.connect.datum.net/access-domain": "database"}}},
	}
	got, err := resolvePolicyGateways(policy, gateways)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "production" {
		t.Fatalf("resolved = %v", got)
	}
}

func TestPolicyRejectsEmptyNegativeAndUnprotectedSelectors(t *testing.T) {
	base := connectv1alpha1.ConnectConnectionPolicy{Spec: connectv1alpha1.ConnectConnectionPolicySpec{GatewaySelector: policySelector(), ConnectorSelector: *policySelector(), Access: connectv1alpha1.ConnectPolicyAccess{Permission: "Network"}}}
	cases := []struct {
		name   string
		mutate func(*connectv1alpha1.ConnectConnectionPolicy)
	}{
		{"empty", func(p *connectv1alpha1.ConnectConnectionPolicy) { p.Spec.GatewaySelector = &metav1.LabelSelector{} }},
		{"negative", func(p *connectv1alpha1.ConnectConnectionPolicy) {
			p.Spec.GatewaySelector.MatchExpressions[0].Operator = metav1.LabelSelectorOpNotIn
		}},
		{"unprotected", func(p *connectv1alpha1.ConnectConnectionPolicy) {
			p.Spec.GatewaySelector.MatchLabels = map[string]string{"user.example/role": "admin"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base.DeepCopy()
			tc.mutate(p)
			if err := validateConnectionPolicy(p); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestGatewayCreatesPlacementsAndKeepsBoundedStatus(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := connectv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "production", Namespace: "project", UID: "gateway-uid", Generation: 4}, Spec: connectv1alpha1.ConnectGatewaySpec{
		ContractVersion: managedGatewayContract, NetworkRef: "network", Placement: &connectv1alpha1.ConnectGatewayPlacementPolicy{LocationSelector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "topology.datum.net/region", Operator: metav1.LabelSelectorOpIn, Values: []string{"us-central-1"}}}}, Availability: connectv1alpha1.ConnectGatewayAvailability{MinReady: 1}},
	}, Status: connectv1alpha1.ConnectGatewayStatus{ClassRef: "legacy", WorkloadRef: "legacy-workload", EndpointID: "legacy-endpoint"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&connectv1alpha1.ConnectGateway{}, &connectv1alpha1.ConnectGatewayPlacement{}).WithObjects(gateway).Build()
	locations := []placementLocation{{Name: "dfw", Topology: map[string]string{"topology.datum.net/region": "us-central-1"}, Ready: true}, {Name: "iad", Topology: map[string]string{"topology.datum.net/region": "us-east-1"}, Ready: true}}
	if err := reconcileManagedGatewayPlacements(ctx, c, gateway, locations); err != nil {
		t.Fatal(err)
	}
	var placements connectv1alpha1.ConnectGatewayPlacementList
	if err := c.List(ctx, &placements); err != nil {
		t.Fatal(err)
	}
	if len(placements.Items) != 1 || placements.Items[0].Spec.LocationRef != "dfw" {
		t.Fatalf("placements = %#v", placements.Items)
	}
	placement := placements.Items[0].DeepCopy()
	placement.Status.ObservedGeneration = placement.Generation
	meta.SetStatusCondition(&placement.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Assigned", ObservedGeneration: placement.Generation})
	if err := c.Status().Update(ctx, placement); err != nil {
		t.Fatal(err)
	}
	var current connectv1alpha1.ConnectGateway
	if err := c.Get(ctx, clientKey(gateway), &current); err != nil {
		t.Fatal(err)
	}
	if err := reconcileManagedGatewayPlacements(ctx, c, &current, locations); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, clientKey(gateway), &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Matched != 1 || current.Status.Ready != 1 || current.Status.Unavailable != 0 {
		t.Fatalf("counts = %+v", current.Status)
	}
	if current.Status.EndpointID != "" || current.Status.WorkloadRef != "" || current.Status.ClassRef != "" {
		t.Fatalf("managed status leaked legacy implementation fields: %+v", current.Status)
	}
	if len(current.Status.Conditions) != 4 {
		t.Fatalf("conditions grew with locations: %v", current.Status.Conditions)
	}
}

func clientKey(object metav1.Object) client.ObjectKey {
	return client.ObjectKey{Namespace: object.GetNamespace(), Name: object.GetName()}
}

func TestApplicablePoliciesComposeAdditively(t *testing.T) {
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Namespace: "project", Labels: map[string]string{"policy.connect.datum.net/environment": "staging", "policy.connect.datum.net/access-domain": "application", "policy.connect.datum.net/developer-access": "true"}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "production", Namespace: "project", Labels: map[string]string{"policy.connect.datum.net/environment": "staging", "policy.connect.datum.net/access-domain": "application", "policy.connect.datum.net/developer-access": "true"}}}
	policies := []connectv1alpha1.ConnectConnectionPolicy{
		{ObjectMeta: metav1.ObjectMeta{Name: "direct", Namespace: "project", Generation: 1}, Spec: connectv1alpha1.ConnectConnectionPolicySpec{GatewayRef: &connectv1alpha1.LocalObjectReference{Name: "production"}, ConnectorSelector: *policySelector(), Access: connectv1alpha1.ConnectPolicyAccess{Permission: "Network"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "selected", Namespace: "project", Generation: 2}, Spec: connectv1alpha1.ConnectConnectionPolicySpec{GatewaySelector: policySelector(), ConnectorSelector: *policySelector(), Access: connectv1alpha1.ConnectPolicyAccess{Permission: "Network"}}},
	}
	revision, count, err := effectivePolicyRevision(policies, connector, gateway, "fd20:0:27::/48")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || len(revision) != 64 {
		t.Fatalf("count=%d revision=%q", count, revision)
	}
}

func TestGatewayPlacementBindingResolution(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := connectv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "production", Namespace: "project", Labels: map[string]string{"policy.connect.datum.net/environment": "staging"}}, Spec: connectv1alpha1.ConnectGatewaySpec{ContractVersion: managedGatewayContract, NetworkRef: "network"}}
	placement := &connectv1alpha1.ConnectGatewayPlacement{ObjectMeta: metav1.ObjectMeta{Name: "production-dfw", Namespace: "project", Labels: map[string]string{"connect.datum.net/gateway": "production"}}, Spec: connectv1alpha1.ConnectGatewayPlacementSpec{GatewayRef: "production", LocationRef: "dfw"}, Status: connectv1alpha1.ConnectGatewayPlacementStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Assigned"}}}}
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "project", Labels: map[string]string{"policy.connect.datum.net/environment": "staging"}}}
	policy := &connectv1alpha1.ConnectConnectionPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow", Namespace: "project", Generation: 1}, Spec: connectv1alpha1.ConnectConnectionPolicySpec{GatewayRef: &connectv1alpha1.LocalObjectReference{Name: "production"}, ConnectorSelector: metav1.LabelSelector{MatchLabels: map[string]string{"policy.connect.datum.net/environment": "staging"}}, Access: connectv1alpha1.ConnectPolicyAccess{Permission: "Network"}}}
	binding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "laptop-production", Namespace: "project", Generation: 2}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: "production", ConnectorRef: "laptop"}, Status: connectv1alpha1.ConnectNetworkBindingStatus{NetworkPlan: &connectv1alpha1.ConnectNetworkPlanSummary{ExpectedPrefix: "fd20:0:27:10:1:1::/96"}}}
	network := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "networking.datumapis.com/v1alpha", "kind": "Network", "metadata": map[string]interface{}{"name": "network", "namespace": "project"}, "status": map[string]interface{}{"ipam": map[string]interface{}{"ipv6Prefix": "fd20:0:27::/48"}}}}
	network.SetGroupVersionKind(schema.GroupVersionKind{Group: "networking.datumapis.com", Version: "v1alpha", Kind: "Network"})
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(binding).WithObjects(gateway, placement, connector, policy, binding, network).Build()
	if err := reconcileManagedNetworkBinding(ctx, c, binding, gateway); err != nil {
		t.Fatal(err)
	}
	var got connectv1alpha1.ConnectNetworkBinding
	if err := c.Get(ctx, clientKey(binding), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.SelectedPlacementRef != placement.Name || len(got.Status.EffectivePolicyRevision) != 64 {
		t.Fatalf("binding status = %+v", got.Status)
	}
	if got.Status.NetworkPlan == nil || len(got.Status.NetworkPlan.DestinationPrefixes) != 1 || got.Status.NetworkPlan.DestinationPrefixes[0] != "fd20:0:27::/48" || got.Status.NetworkPlan.MTU != 1280 {
		t.Fatalf("network plan = %+v", got.Status.NetworkPlan)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") {
		t.Fatalf("conditions = %v", got.Status.Conditions)
	}
}
