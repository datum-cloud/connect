package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testClient(t *testing.T, objs ...runtime.Object) *fake.ClientBuilder {
	t.Helper()
	s := runtime.NewScheme()
	if err := connectv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := coordinationv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objs...).WithStatusSubresource(&connectv1alpha1.Connector{}, &connectv1alpha1.ConnectorClass{}, &connectv1alpha1.ConnectorAdvertisement{}, &connectv1alpha1.ConnectGateway{})
}

func TestReconcileConnectorChecksPlatformClass(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "laptop", UID: types.UID("laptop-uid")}, Spec: connectv1alpha1.ConnectorSpec{ClassRef: "masque", PublicKey: strings.Repeat("a", 64)}}
	projectClient := testClient(t, connector).Build()
	classClient := testClient(t).Build()
	if err := reconcileConnector(ctx, projectClient, classClient, connector); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(connector.Status.Conditions, "Accepted").Reason; got != "ClassNotFound" {
		t.Fatalf("reason=%q, want ClassNotFound", got)
	}

	class := &connectv1alpha1.ConnectorClass{ObjectMeta: metav1.ObjectMeta{Name: "masque"}, Spec: connectv1alpha1.ConnectorClassSpec{Transports: []string{"masque-v1"}}}
	classClient = testClient(t, class).Build()
	if err := reconcileConnector(ctx, projectClient, classClient, connector); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(connector.Status.Conditions, "Accepted").Status; got != metav1.ConditionTrue {
		t.Fatalf("accepted=%q, want True", got)
	}
	if got := meta.FindStatusCondition(connector.Status.Conditions, "Ready").Reason; got != "AgentOffline" {
		t.Fatalf("ready reason=%q, want AgentOffline until the agent renews its Lease", got)
	}
	var lease coordinationv1.Lease
	if err := projectClient.Get(ctx, types.NamespacedName{Name: "laptop"}, &lease); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewMicroTime(time.Now())
	lease.Spec.RenewTime = &now
	if err := projectClient.Update(ctx, &lease); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, connector); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(connector.Status.Conditions, "Ready").Status; got != metav1.ConditionTrue {
		t.Fatalf("ready=%q after Lease renewal, want True", got)
	}
}

func TestReconcileGatewayReportsUnimplementedNetworkIntegration(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "router"}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Spec: connectv1alpha1.ConnectGatewaySpec{ConnectorRef: "router", NetworkRef: "private-net"}}
	c := testClient(t, connector, gateway).Build()
	if err := reconcileGateway(ctx, c, gateway); err != nil {
		t.Fatal(err)
	}
	condition := gateway.Status.Conditions[0]
	if condition.Status != metav1.ConditionUnknown || condition.Reason != "IntegrationPending" {
		t.Fatalf("condition=%#v", condition)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "vpc"}, &connectv1alpha1.ConnectGateway{}); err != nil {
		t.Fatal(err)
	}
}
