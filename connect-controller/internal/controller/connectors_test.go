package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"}, &unstructured.Unstructured{})
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "WorkloadList"}, &unstructured.UnstructuredList{})
	return fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objs...).WithStatusSubresource(&connectv1alpha1.Connector{}, &connectv1alpha1.ConnectorClass{}, &connectv1alpha1.ConnectorAdvertisement{}, &connectv1alpha1.ConnectGateway{}, &connectv1alpha1.ConnectNetworkBinding{})
}

func TestReconcileConnectorChecksPlatformClass(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "laptop", UID: types.UID("laptop-uid")}, Spec: connectv1alpha1.ConnectorSpec{ClassRef: "masque", PublicKey: strings.Repeat("a", 64)}}
	legacyController := true
	legacyLease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
		Name: "laptop",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "networking.datumapis.com/v1alpha1",
			Kind:       "Connector",
			Name:       "laptop",
			UID:        types.UID("legacy-laptop-uid"),
			Controller: &legacyController,
		}},
	}}
	projectClient := testClient(t, connector, legacyLease).Build()
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
	var preservedLegacyLease coordinationv1.Lease
	if err := projectClient.Get(ctx, types.NamespacedName{Name: "laptop"}, &preservedLegacyLease); err != nil {
		t.Fatal(err)
	}
	if got := preservedLegacyLease.OwnerReferences[0].UID; got != types.UID("legacy-laptop-uid") {
		t.Fatalf("legacy Lease owner UID=%q, want it preserved", got)
	}
}

func TestReconcileGatewayCreatesComputeWorkloadAndApprovesConnectorBinding(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("a", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "vpc-gateway", Namespace: "project", UID: types.UID("gateway-uid")}, Spec: connectv1alpha1.ConnectGatewaySpec{NetworkRef: "private-net", LocationRef: "DFW", Routes: []string{"fd20:0:27::/48"}, Image: "ghcr.io/datum-cloud/iroh-gateway:connect-ip"}}
	c := testClient(t, connector, gateway).Build()
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
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
	selector, ok := placement["locationSelector"].(map[string]interface{})
	if !ok || selector["matchLabels"].(map[string]interface{})["topology.datum.net/city-code"] != "DFW" {
		t.Fatalf("locationSelector=%v, want DFW city-code selector", placement["locationSelector"])
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
	if err := c.Create(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := reconcileNetworkBinding(ctx, c, "project-id", binding); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(binding.Status.Conditions, "Accepted"); condition == nil || condition.Status != metav1.ConditionUnknown || condition.Reason != "GatewayApplyingGrant" || binding.Status.AssignedAddress == "" || binding.Status.PeerAddress == "" {
		t.Fatalf("binding should wait for the grant rollout and have addresses: %#v", binding.Status)
	}
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
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
	if len(config.Grants) != 1 {
		t.Fatalf("grants=%v, want the approved Connector grant", config.Grants)
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
	if err := reconcileNetworkBinding(ctx, c, "project-id", binding); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(binding.Status.Conditions, "Accepted") {
		t.Fatalf("binding should be accepted only after the gateway applies its grant: %#v", binding.Status.Conditions)
	}
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(gateway.Status.Conditions, "Ready") {
		t.Fatalf("gateway should be ready after Compute Workload Available: %#v", gateway.Status.Conditions)
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
	spec := connectv1alpha1.ConnectGatewaySpec{NetworkRef: "vpc", LocationRef: "DFW", Image: "gateway:dev", Routes: []string{"::/0"}}
	if err := validateGatewaySpec(spec); err == nil {
		t.Fatal("expected default route to be rejected for relay-only gateway")
	}
}
