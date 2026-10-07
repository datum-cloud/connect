package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"}, &unstructured.Unstructured{})
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "WorkloadList"}, &unstructured.UnstructuredList{})
	return fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objs...).WithStatusSubresource(&connectv1alpha1.Connector{}, &connectv1alpha1.ConnectorClass{}, &connectv1alpha1.ConnectGatewayClass{}, &connectv1alpha1.ConnectorAdvertisement{}, &connectv1alpha1.ConnectGateway{}, &connectv1alpha1.ConnectNetworkBinding{})
}

func testGatewayClass(t *testing.T, mode string, idleTimeout time.Duration) (*connectv1alpha1.ConnectGatewayClass, client.Client) {
	t.Helper()
	parameters := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "standard-gateway", Namespace: "connect-system"}, Data: map[string]string{
		"image":        "ghcr.io/datum-cloud/iroh-gateway:connect-ip",
		"instanceType": "datumcloud/d1-standard-2",
	}}
	class := &connectv1alpha1.ConnectGatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "standard"},
		Spec: connectv1alpha1.ConnectGatewayClassSpec{
			ControllerName: gatewayControllerName,
			ParametersRef:  connectv1alpha1.ConnectGatewayClassParametersReference{Name: parameters.Name, Namespace: parameters.Namespace},
			Scaling:        connectv1alpha1.ConnectGatewayScalingPolicy{Mode: mode, IdleTimeout: metav1.Duration{Duration: idleTimeout}},
		},
		Status: connectv1alpha1.ConnectGatewayClassStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}},
	}
	return class, testClient(t, parameters).Build()
}

func reconcileTestGateway(t *testing.T, ctx context.Context, c client.Client, gateway *connectv1alpha1.ConnectGateway) {
	t.Helper()
	class, parameterClient := testGatewayClass(t, "AlwaysOn", 0)
	if err := c.Create(ctx, class); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	if err := reconcileGateway(ctx, c, parameterClient, "project-id", gateway, time.Now()); err != nil {
		t.Fatal(err)
	}
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
	if got, want := connector.Status.LeaseRef, connectorLeaseName(connector.Name); got != want {
		t.Fatalf("leaseRef=%q, want Connect-specific Lease %q", got, want)
	}
	var lease coordinationv1.Lease
	if err := projectClient.Get(ctx, types.NamespacedName{Name: connectorLeaseName(connector.Name)}, &lease); err != nil {
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

func TestReconcileProjectedConnectorClassProjectsBackingReadiness(t *testing.T) {
	ctx := context.Background()
	spec := connectv1alpha1.ConnectorClassSpec{
		Capabilities: []string{"connect-tcp", "connect-udp", "connect-ip"},
		Transports:   []string{"masque-v1"},
	}
	projectClass := &connectv1alpha1.ConnectorClass{
		ObjectMeta: metav1.ObjectMeta{Name: "connect-staging-masque-v1", Generation: 2},
		Spec:       spec,
	}
	backingClass := &connectv1alpha1.ConnectorClass{
		ObjectMeta: metav1.ObjectMeta{Name: projectClass.Name, Generation: 4},
		Spec:       spec,
		Status: connectv1alpha1.ConnectorClassStatus{
			ObservedGeneration: 4,
			Conditions: []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Valid",
				ObservedGeneration: 4,
			}},
		},
	}
	projectClient := testClient(t, projectClass).Build()
	if err := reconcileProjectedClass(ctx, projectClient, testClient(t, backingClass).Build(), projectClass); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(projectClass.Status.Conditions, "Ready")
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "BackingClassReady" {
		t.Fatalf("projected condition=%#v, want Ready=True with reason BackingClassReady", condition)
	}
	if condition.ObservedGeneration != projectClass.Generation || projectClass.Status.ObservedGeneration != projectClass.Generation {
		t.Fatalf("projected status did not observe generation %d: %#v", projectClass.Generation, projectClass.Status)
	}
}

func TestReconcileProjectedConnectorClassReportsUnavailableBackingClass(t *testing.T) {
	ctx := context.Background()
	projectClass := &connectv1alpha1.ConnectorClass{
		ObjectMeta: metav1.ObjectMeta{Name: "connect-staging-masque-v1", Generation: 1},
		Spec: connectv1alpha1.ConnectorClassSpec{
			Capabilities: []string{"connect-tcp", "connect-udp", "connect-ip"},
			Transports:   []string{"masque-v1"},
		},
	}
	projectClient := testClient(t, projectClass).Build()
	if err := reconcileProjectedClass(ctx, projectClient, testClient(t).Build(), projectClass); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(projectClass.Status.Conditions, "Ready")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "BackingClassNotFound" {
		t.Fatalf("projected condition=%#v, want Ready=False with reason BackingClassNotFound", condition)
	}
}

func TestReconcileProjectedConnectorClassRequiresCurrentReadyBackingStatus(t *testing.T) {
	ctx := context.Background()
	spec := connectv1alpha1.ConnectorClassSpec{Transports: []string{"masque-v1"}}
	projectClass := &connectv1alpha1.ConnectorClass{ObjectMeta: metav1.ObjectMeta{Name: "masque", Generation: 1}, Spec: spec}
	backingClass := &connectv1alpha1.ConnectorClass{
		ObjectMeta: metav1.ObjectMeta{Name: projectClass.Name, Generation: 2},
		Spec:       spec,
		Status: connectv1alpha1.ConnectorClassStatus{Conditions: []metav1.Condition{{
			Type: "Ready", Status: metav1.ConditionTrue, Reason: "Valid", ObservedGeneration: 1,
		}}},
	}
	if err := reconcileProjectedClass(ctx, testClient(t, projectClass).Build(), testClient(t, backingClass).Build(), projectClass); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(projectClass.Status.Conditions, "Ready")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "BackingClassNotReady" {
		t.Fatalf("projected condition=%#v, want stale backing status to be not ready", condition)
	}
}

func TestGatewayClassReportsParameterReadiness(t *testing.T) {
	ctx := context.Background()
	class := &connectv1alpha1.ConnectGatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "standard", Generation: 2},
		Spec: connectv1alpha1.ConnectGatewayClassSpec{
			ControllerName: gatewayControllerName,
			ParametersRef:  connectv1alpha1.ConnectGatewayClassParametersReference{Name: "standard-gateway", Namespace: "connect-system"},
			Scaling:        connectv1alpha1.ConnectGatewayScalingPolicy{Mode: "OnDemand", IdleTimeout: metav1.Duration{Duration: 10 * time.Minute}},
		},
	}
	projectClient := testClient(t, class).Build()
	parameterClient := testClient(t).Build()
	if err := reconcileGatewayClass(ctx, projectClient, parameterClient, class); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(class.Status.Conditions, "Ready"); condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "ParametersNotReady" {
		t.Fatalf("class condition=%#v, want missing parameters to make it not ready", condition)
	}
	parameters := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "standard-gateway", Namespace: "connect-system"}, Data: map[string]string{"image": "gateway:v2", "instanceType": "datumcloud/d1-standard-4"}}
	if err := parameterClient.Create(ctx, parameters); err != nil {
		t.Fatal(err)
	}
	if err := reconcileGatewayClass(ctx, projectClient, parameterClient, class); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(class.Status.Conditions, "Accepted") || !meta.IsStatusConditionTrue(class.Status.Conditions, "Ready") || class.Status.ObservedGeneration != class.Generation {
		t.Fatalf("class should be accepted and ready with valid operator parameters: %#v", class.Status)
	}
}

func TestGatewayClassRejectsInvalidRelayURLs(t *testing.T) {
	ctx := context.Background()
	class, parameterClient := testGatewayClass(t, "OnDemand", 10*time.Minute)
	class.Spec.RelayURLs = []string{"http://relay.example", "https://relay.example?token=secret"}
	projectClient := testClient(t, class).Build()
	if err := reconcileGatewayClass(ctx, projectClient, parameterClient, class); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(class.Status.Conditions, "Accepted")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "InvalidParameters" {
		t.Fatalf("class condition=%#v, want invalid relay URLs to be rejected", condition)
	}
}

func TestOnDemandGatewayScalesBetweenZeroAndOne(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, time.October, 5, 12, 0, 0, 0, time.UTC)
	connector := &connectv1alpha1.Connector{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "project"},
		Spec:       connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("a", 64)},
		Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{
			{Type: "Accepted", Status: metav1.ConditionTrue},
			{Type: "Ready", Status: metav1.ConditionTrue},
		}},
	}
	gateway := &connectv1alpha1.ConnectGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "project", UID: types.UID("gateway-uid"), Generation: 1},
		Spec:       connectv1alpha1.ConnectGatewaySpec{GatewayClassRef: "standard", NetworkRef: "private-net", LocationRef: "us-central-1", Routes: []string{"fd20::/48"}},
	}
	// The binding is intentionally not Ready. Workload activity derives from
	// binding intent plus Connector conditions, never binding readiness.
	binding := &connectv1alpha1.ConnectNetworkBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop-vpc", Namespace: "project"},
		Spec:       connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: connector.Name},
		Status:     connectv1alpha1.ConnectNetworkBindingStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionFalse}}},
	}
	class, parameterClient := testGatewayClass(t, "OnDemand", 10*time.Minute)
	c := testClient(t, connector, gateway, binding, class).Build()
	if err := reconcileGateway(ctx, c, parameterClient, "project-id", gateway, t0); err != nil {
		t.Fatal(err)
	}
	endpointID := gateway.Status.EndpointID
	workloadName := gateway.Status.WorkloadRef
	if endpointID == "" || workloadName == "" || gateway.Status.IdleSince != nil {
		t.Fatalf("active gateway did not scale up correctly: %#v", gateway.Status)
	}

	storedConnector := &connectv1alpha1.Connector{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(connector), storedConnector); err != nil {
		t.Fatal(err)
	}
	meta.SetStatusCondition(&storedConnector.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: "AgentOffline"})
	if err := c.Status().Update(ctx, storedConnector); err != nil {
		t.Fatal(err)
	}
	if err := reconcileGateway(ctx, c, parameterClient, "project-id", gateway, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if gateway.Status.IdleSince == nil || gateway.Status.WorkloadRef != workloadName {
		t.Fatalf("idle grace period should retain the Workload: %#v", gateway.Status)
	}
	if err := reconcileGateway(ctx, c, parameterClient, "project-id", gateway, t0.Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	workload := &unstructured.Unstructured{}
	workload.SetGroupVersionKind(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"})
	if err := c.Get(ctx, types.NamespacedName{Name: workloadName, Namespace: gateway.Namespace}, workload); err == nil {
		t.Fatal("idle Workload still exists after the class grace period")
	}
	if gateway.Status.WorkloadRef != "" || gateway.Status.Phase != "Dormant" || !meta.IsStatusConditionTrue(gateway.Status.Conditions, "Dormant") {
		t.Fatalf("gateway should report Dormant after scale down: %#v", gateway.Status)
	}
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "identity"), Namespace: gateway.Namespace}, secret); err != nil {
		t.Fatalf("gateway identity was not preserved while dormant: %v", err)
	}
	config := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: gateway.Namespace}, config); err != nil || !strings.Contains(config.Data["grants.json"], connector.Spec.PublicKey) {
		t.Fatalf("durable grants were not preserved while dormant: config=%#v err=%v", config.Data, err)
	}

	meta.SetStatusCondition(&storedConnector.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "ConnectorReady"})
	if err := c.Status().Update(ctx, storedConnector); err != nil {
		t.Fatal(err)
	}
	if err := reconcileGateway(ctx, c, parameterClient, "project-id", gateway, t0.Add(13*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if gateway.Status.WorkloadRef != workloadName || gateway.Status.EndpointID != endpointID || gateway.Status.IdleSince != nil {
		t.Fatalf("gateway did not wake with its stable identity and Workload name: %#v", gateway.Status)
	}
}

func TestReconcileGatewayCreatesComputeWorkloadAndApprovesConnectorBinding(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("a", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	secondConnector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "phone", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("b", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "vpc-gateway", Namespace: "project", UID: types.UID("gateway-uid")}, Spec: connectv1alpha1.ConnectGatewaySpec{GatewayClassRef: "standard", NetworkRef: "private-net", LocationRef: "us-central-1", Routes: []string{"fd20:0:27::/48"}, PeerRouting: true}}
	c := testClient(t, connector, secondConnector, gateway).Build()
	reconcileTestGateway(t, ctx, c, gateway)
	if gateway.Status.EndpointID == "" || gateway.Status.WorkloadRef == "" {
		t.Fatalf("gateway status missing endpoint or workload ref: %#v", gateway.Status)
	}
	workload := &unstructured.Unstructured{}
	workload.SetGroupVersionKind(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"})
	if err := c.Get(ctx, types.NamespacedName{Name: gateway.Status.WorkloadRef, Namespace: "project"}, workload); err != nil {
		t.Fatal(err)
	}
	deploymentLabel := workload.GetName() + "-gateway-us-central-1"
	if len(deploymentLabel) > 63 {
		t.Fatalf("generated WorkloadDeployment name %q exceeds Kubernetes label limit", deploymentLabel)
	}
	initialConfigHash, found, err := unstructured.NestedString(workload.Object, "spec", "template", "metadata", "annotations", "connect.datumapis.com/config-hash")
	if err != nil || !found || initialConfigHash == "" {
		t.Fatalf("initial config hash=%q found=%t err=%v", initialConfigHash, found, err)
	}
	placements, found, err := unstructured.NestedSlice(workload.Object, "spec", "placements")
	if err != nil || !found || len(placements) != 1 {
		t.Fatalf("placements=%v found=%t err=%v, want one", placements, found, err)
	}
	placement, ok := placements[0].(map[string]interface{})
	if !ok {
		t.Fatalf("placement=%T, want map", placements[0])
	}
	locations, ok := placement["locations"].([]interface{})
	if !ok || len(locations) != 1 || locations[0].(map[string]interface{})["name"] != "us-central-1" {
		t.Fatalf("locations=%v, want us-central-1 location reference", placement["locations"])
	}
	scaleSettings, ok := placement["scaleSettings"].(map[string]interface{})
	if !ok || scaleSettings["instanceManagementPolicy"] != "OrderedReady" {
		t.Fatalf("scaleSettings=%v, want explicitly declared OrderedReady policy", placement["scaleSettings"])
	}
	if scale, ok := placement["scaleSettings"].(map[string]interface{}); !ok || scale["minReplicas"] != int64(1) || scale["maxReplicas"] != nil {
		t.Fatalf("scaleSettings=%v, want minReplicas=1 without maxReplicas", placement["scaleSettings"])
	}
	instanceType, found, err := unstructured.NestedString(workload.Object, "spec", "template", "spec", "runtime", "resources", "instanceType")
	if err != nil || !found || instanceType != "datumcloud/d1-standard-2" {
		t.Fatalf("instanceType=%q found=%t err=%v, want datumcloud/d1-standard-2", instanceType, found, err)
	}
	interfaces, _, _ := unstructured.NestedSlice(workload.Object, "spec", "template", "spec", "networkInterfaces")
	if len(interfaces) != 1 {
		t.Fatalf("network interfaces=%v, want one VPC interface", interfaces)
	}
	attachments, _, _ := unstructured.NestedSlice(workload.Object, "spec", "template", "spec", "runtime", "sandbox", "containers")
	if len(attachments) != 1 {
		t.Fatalf("gateway containers=%v, want one", attachments)
	}
	container, ok := attachments[0].(map[string]interface{})
	if !ok {
		t.Fatalf("gateway container=%T, want map", attachments[0])
	}
	if container["image"] != "ghcr.io/datum-cloud/iroh-gateway:connect-ip" {
		t.Fatalf("gateway image=%v, want operator class parameter", container["image"])
	}
	command, _, _ := unstructured.NestedStringSlice(container, "command")
	if len(command) != 2 || command[0] != "/bin/sh" {
		t.Fatalf("gateway command=%v, want TUN setup wrapper", command)
	}
	args, _, _ := unstructured.NestedStringSlice(container, "args")
	if len(args) != 1 || !strings.Contains(args[0], "mknod /dev/net/tun c 10 200") || !strings.Contains(args[0], "install -D -m 600 /etc/connect/key/key /run/connect-inputs/key") || !strings.Contains(args[0], "install -D -m 600 /etc/connect/gateway/grants.json /run/connect-inputs/grants.json") || !strings.Contains(args[0], "--config-file=/run/connect-inputs/gateway.yaml --key-file=/run/connect-inputs/key") {
		t.Fatalf("gateway args=%v, want TUN setup and safe staging of projected Secret/ConfigMap files", args)
	}
	if !strings.Contains(args[0], "--ip-config=/run/connect-inputs/grants.json") {
		t.Fatalf("gateway args=%v, want the strict IP grants loader to read the regular-file copy", args)
	}
	if !strings.Contains(args[0], "--metrics-addr=127.0.0.1 --metrics-port=9090") {
		t.Fatalf("gateway metrics must be available only on loopback: %s", args[0])
	}
	securityContext, ok := container["securityContext"].(map[string]interface{})
	if !ok {
		t.Fatalf("gateway securityContext=%T, want map", container["securityContext"])
	}
	capabilities, ok := securityContext["capabilities"].(map[string]interface{})
	if !ok {
		t.Fatalf("gateway capabilities=%T, want map", securityContext["capabilities"])
	}
	added, ok := capabilities["add"].([]interface{})
	if !ok || len(added) != 2 || added[0] != "NET_ADMIN" || added[1] != "MKNOD" {
		t.Fatalf("gateway capabilities=%v, want NET_ADMIN and MKNOD", capabilities["add"])
	}

	binding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "laptop-vpc", Namespace: "project", Generation: 1}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: connector.Name}}
	secondBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "phone-vpc", Namespace: "project", Generation: 1}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: secondConnector.Name}}
	// Create bindings in reverse peer-key order to ensure the rendered grants
	// are deterministic rather than dependent on API list order.
	for _, item := range []*connectv1alpha1.ConnectNetworkBinding{secondBinding, binding} {
		if err := c.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		if err := reconcileNetworkBinding(ctx, c, "project-id", item); err != nil {
			t.Fatal(err)
		}
		if condition := meta.FindStatusCondition(item.Status.Conditions, "Accepted"); condition == nil || condition.Status != metav1.ConditionUnknown || condition.Reason != "GatewayApplyingGrant" || item.Status.AssignedAddress == "" || item.Status.PeerAddress == "" {
			t.Fatalf("binding should wait for the grant rollout and have addresses: %#v", item.Status)
		}
	}
	if binding.Status.AssignedAddress == secondBinding.Status.AssignedAddress || binding.Status.PeerAddress == secondBinding.Status.PeerAddress {
		t.Fatalf("distinct Connectors received overlapping attachment addresses: first=%#v second=%#v", binding.Status, secondBinding.Status)
	}
	reconcileTestGateway(t, ctx, c, gateway)
	if err := c.Get(ctx, types.NamespacedName{Name: gateway.Status.WorkloadRef, Namespace: "project"}, workload); err != nil {
		t.Fatal(err)
	}
	updatedConfigHash, found, err := unstructured.NestedString(workload.Object, "spec", "template", "metadata", "annotations", "connect.datumapis.com/config-hash")
	if err != nil || !found || updatedConfigHash == initialConfigHash {
		t.Fatalf("updated config hash=%q initial=%q found=%t err=%v; expected grant changes to roll the Workload", updatedConfigHash, initialConfigHash, found, err)
	}
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: "project"}, configMap); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Grants []map[string]interface{} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(configMap.Data["grants.json"]), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Grants) != 2 {
		t.Fatalf("grants=%v, want both approved Connector grants", config.Grants)
	}
	if config.Grants[0]["peer"] != connector.Spec.PublicKey || config.Grants[1]["peer"] != secondConnector.Spec.PublicKey {
		t.Fatalf("grants are not sorted by peer identity: %v", config.Grants)
	}
	firstPeerRoutes, ok := config.Grants[0]["peer_routes"].([]interface{})
	if !ok || len(firstPeerRoutes) != 1 || firstPeerRoutes[0] != config.Grants[1]["client_address"] {
		t.Fatalf("first grant peer_routes=%v, want second Connector address %v", config.Grants[0]["peer_routes"], config.Grants[1]["client_address"])
	}
	secondPeerRoutes, ok := config.Grants[1]["peer_routes"].([]interface{})
	if !ok || len(secondPeerRoutes) != 1 || secondPeerRoutes[0] != config.Grants[0]["client_address"] {
		t.Fatalf("second grant peer_routes=%v, want first Connector address %v", config.Grants[1]["peer_routes"], config.Grants[0]["client_address"])
	}
	grantInterfaces := map[string]bool{}
	addresses := map[string]bool{}
	for _, grant := range config.Grants {
		peer, _ := grant["peer"].(string)
		interfaceName, _ := grant["interface_name"].(string)
		clientAddress, _ := grant["client_address"].(string)
		gatewayAddress, _ := grant["gateway_address"].(string)
		if len(interfaceName) == 0 || len(interfaceName) > 15 || grantInterfaces[interfaceName] {
			t.Fatalf("grant for %q has invalid or duplicate interface %q: %v", peer, interfaceName, config.Grants)
		}
		grantInterfaces[interfaceName] = true
		for _, address := range []string{clientAddress, gatewayAddress} {
			if address == "" || addresses[address] {
				t.Fatalf("grant for %q has empty or duplicate address %q: %v", peer, address, config.Grants)
			}
			addresses[address] = true
		}
	}
	originalGrantJSON := configMap.Data["grants.json"]
	duplicateBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "laptop-vpc-alias", Namespace: "project", Generation: 1}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: connector.Name}}
	if err := c.Create(ctx, duplicateBinding); err != nil {
		t.Fatal(err)
	}
	reconcileTestGateway(t, ctx, c, gateway)
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: "project"}, configMap); err != nil {
		t.Fatal(err)
	}
	if configMap.Data["grants.json"] != originalGrantJSON {
		t.Fatalf("duplicate binding changed the canonical gateway grants: before=%s after=%s", originalGrantJSON, configMap.Data["grants.json"])
	}
	if err := unstructured.SetNestedSlice(workload.Object, []interface{}{map[string]interface{}{"type": "Available", "status": "True"}}, "status", "conditions"); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]interface{}{
		"observedGeneration": workload.GetGeneration(),
		"desiredReplicas":    int64(1),
		"readyReplicas":      int64(1),
		"updatedReplicas":    int64(1),
	} {
		if err := unstructured.SetNestedField(workload.Object, value, "status", path); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Update(ctx, workload); err != nil {
		t.Fatal(err)
	}
	for _, item := range []*connectv1alpha1.ConnectNetworkBinding{binding, secondBinding} {
		if err := reconcileNetworkBinding(ctx, c, "project-id", item); err != nil {
			t.Fatal(err)
		}
		if !meta.IsStatusConditionTrue(item.Status.Conditions, "Accepted") {
			t.Fatalf("binding should be accepted only after the gateway applies its grant: %#v", item.Status.Conditions)
		}
	}
	if got, want := binding.Status.Routes, []string{"fd20:0:27::/48", secondBinding.Status.AssignedAddress}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first binding routes=%v, want VPC and second Connector routes %v", got, want)
	}
	if got, want := secondBinding.Status.Routes, []string{"fd20:0:27::/48", binding.Status.AssignedAddress}; !reflect.DeepEqual(got, want) {
		t.Fatalf("second binding routes=%v, want VPC and first Connector routes %v", got, want)
	}
	reconcileTestGateway(t, ctx, c, gateway)
	if !meta.IsStatusConditionTrue(gateway.Status.Conditions, "Ready") {
		t.Fatalf("gateway should be ready after Compute Workload Available: %#v", gateway.Status.Conditions)
	}
}

func TestGatewayGrantInterfaceDerivationIsPerPeerAndSymmetric(t *testing.T) {
	gateway := strings.Repeat("f", 64)
	first := strings.Repeat("1", 64)
	second := strings.Repeat("2", 64)
	_, _, firstInterface := gatewayPeerAddresses("project", "vpc", first, gateway)
	_, _, reverseFirstInterface := gatewayPeerAddresses("project", "vpc", gateway, first)
	_, _, secondInterface := gatewayPeerAddresses("project", "vpc", second, gateway)
	if firstInterface != reverseFirstInterface {
		t.Fatalf("interface derivation is not symmetric: %q != %q", firstInterface, reverseFirstInterface)
	}
	if firstInterface == secondInterface {
		t.Fatalf("distinct peers share interface %q", firstInterface)
	}
	if len(firstInterface) > 15 || len(secondInterface) > 15 {
		t.Fatalf("interface names exceed Linux IFNAMSIZ: %q %q", firstInterface, secondInterface)
	}
}

func TestGatewayGrantPersistsWhenConnectorIsTemporarilyOffline(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "project"},
		Spec:       connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("a", 64)},
		Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{
			{Type: "Accepted", Status: metav1.ConditionTrue},
			{Type: "Ready", Status: metav1.ConditionFalse, Reason: "AgentOffline"},
		}},
	}
	gateway := &connectv1alpha1.ConnectGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-gateway", Namespace: "project", UID: types.UID("gateway-uid")},
		Spec:       connectv1alpha1.ConnectGatewaySpec{GatewayClassRef: "standard", NetworkRef: "private-net", LocationRef: "us-central-1", Routes: []string{"fd20:0:27::/48"}},
	}
	binding := &connectv1alpha1.ConnectNetworkBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop-vpc", Namespace: "project"},
		Spec:       connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: connector.Name},
	}
	c := testClient(t, connector, gateway, binding).Build()
	if err := reconcileGatewayResources(ctx, c, "project-id", gateway, gatewayClassConfig{image: "gateway:dev", instanceType: "datumcloud/d1-standard-2", mode: "AlwaysOn"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: gateway.Namespace}, configMap); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Grants []struct {
			Peer string `json:"peer"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(configMap.Data["grants.json"]), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Grants) != 1 || config.Grants[0].Peer != connector.Spec.PublicKey {
		t.Fatalf("gateway grants=%v, want offline but authorized Connector %q to retain its grant", config.Grants, connector.Spec.PublicKey)
	}
	if !meta.IsStatusConditionTrue(connector.Status.Conditions, "Accepted") || meta.IsStatusConditionTrue(connector.Status.Conditions, "Ready") {
		t.Fatalf("test Connector conditions=%v, want Accepted=True and Ready=False", connector.Status.Conditions)
	}
	if err := reconcileNetworkBinding(ctx, c, "project-id", binding); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(binding.Status.Conditions, "Accepted")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "ConnectorNotReady" {
		t.Fatalf("binding condition=%#v, want ConnectorNotReady while the Connector is offline", condition)
	}
}

func TestPeerRoutingIsDisabledByDefault(t *testing.T) {
	ctx := context.Background()
	first := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("1", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	second := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("2", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "project", UID: types.UID("gateway-uid")}, Spec: connectv1alpha1.ConnectGatewaySpec{GatewayClassRef: "standard", NetworkRef: "private-net", LocationRef: "us-central-1", Routes: []string{"fd20::/48"}}}
	firstBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "first-vpc", Namespace: "project"}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: first.Name}}
	secondBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "second-vpc", Namespace: "project"}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: second.Name}}
	c := testClient(t, first, second, gateway, firstBinding, secondBinding).Build()
	reconcileTestGateway(t, ctx, c, gateway)
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: gateway.Namespace}, configMap); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Grants []map[string]interface{} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(configMap.Data["grants.json"]), &config); err != nil {
		t.Fatal(err)
	}
	for _, grant := range config.Grants {
		if _, found := grant["peer_routes"]; found {
			t.Fatalf("peer_routes must be omitted unless explicitly enabled: %v", grant)
		}
	}
	if err := reconcileNetworkBinding(ctx, c, "project-id", firstBinding); err != nil {
		t.Fatal(err)
	}
	if got, want := firstBinding.Status.Routes, gateway.Spec.Routes; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes=%v, want only VPC routes %v", got, want)
	}
}

func TestGatewayReportsPeerRouteCapacityExceeded(t *testing.T) {
	ctx := context.Background()
	routes := make([]string, 32)
	for index := range routes {
		routes[index] = fmt.Sprintf("fd20::%x/128", index+1)
	}
	first := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("1", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	second := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("2", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "project", UID: types.UID("gateway-uid")}, Spec: connectv1alpha1.ConnectGatewaySpec{GatewayClassRef: "standard", NetworkRef: "private-net", LocationRef: "us-central-1", Routes: routes, PeerRouting: true}}
	firstBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "first-vpc", Namespace: "project"}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: first.Name}}
	secondBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "second-vpc", Namespace: "project"}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: second.Name}}
	c := testClient(t, first, second, gateway, firstBinding, secondBinding).Build()
	reconcileTestGateway(t, ctx, c, gateway)
	condition := meta.FindStatusCondition(gateway.Status.Conditions, "Ready")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "PeerRouteCapacityExceeded" {
		t.Fatalf("gateway condition=%#v, want PeerRouteCapacityExceeded", condition)
	}
	if err := reconcileNetworkBinding(ctx, c, "project-id", firstBinding); err != nil {
		t.Fatal(err)
	}
	bindingCondition := meta.FindStatusCondition(firstBinding.Status.Conditions, "Accepted")
	if bindingCondition == nil || bindingCondition.Status != metav1.ConditionFalse || bindingCondition.Reason != "PeerRouteCapacityExceeded" || firstBinding.Status.Routes != nil {
		t.Fatalf("binding status=%#v, want route-capacity rejection without advertised routes", firstBinding.Status)
	}
}

func TestGatewayPeerAddressDerivationIsSymmetric(t *testing.T) {
	client := strings.Repeat("1", 64)
	gateway := strings.Repeat("2", 64)
	clientAddress, gatewayAddress, interfaceName := gatewayPeerAddresses("project", "vpc", client, gateway)
	reverseClientAddress, reverseGatewayAddress, reverseInterfaceName := gatewayPeerAddresses("project", "vpc", gateway, client)
	if clientAddress != reverseGatewayAddress || gatewayAddress != reverseClientAddress {
		t.Fatalf("addresses are not symmetric: (%s, %s) vs (%s, %s)", clientAddress, gatewayAddress, reverseClientAddress, reverseGatewayAddress)
	}
	if interfaceName != reverseInterfaceName {
		t.Fatalf("interface name is not symmetric: %q vs %q", interfaceName, reverseInterfaceName)
	}
	if len(interfaceName) > 15 {
		t.Fatalf("interface name %q exceeds Linux's 15-character limit", interfaceName)
	}
	_, _, secondInterfaceName := gatewayPeerAddresses("project", "vpc", strings.Repeat("3", 64), gateway)
	if interfaceName == secondInterfaceName {
		t.Fatalf("two Connector grants on one gateway share interface name %q", interfaceName)
	}
}

func TestSortGatewayBindingsMakesGrantOrderDeterministic(t *testing.T) {
	bindings := []connectv1alpha1.ConnectNetworkBinding{
		{ObjectMeta: metav1.ObjectMeta{Name: "connector-z"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "connector-a"}},
	}
	sortGatewayBindings(bindings)
	if bindings[0].Name != "connector-a" || bindings[1].Name != "connector-z" {
		t.Fatalf("binding order = [%s, %s], want stable alphabetical order", bindings[0].Name, bindings[1].Name)
	}
}

func TestGatewayRejectsDefaultRoute(t *testing.T) {
	spec := connectv1alpha1.ConnectGatewaySpec{GatewayClassRef: "standard", NetworkRef: "vpc", LocationRef: "us-central-1", Routes: []string{"::/0"}}
	if err := validateGatewaySpec(spec); err == nil {
		t.Fatal("expected default route to be rejected for relay-only gateway")
	}
}
