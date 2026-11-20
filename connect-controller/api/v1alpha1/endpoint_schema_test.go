package v1alpha1

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

func TestEndpointCRDSchema(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS to run real API schema validation")
	}
	environment := &envtest.Environment{}
	for _, plural := range []string{"connectendpoints", "connectgrants", "connectgateways", "connectnetworkbindings"} {
		encoded, err := os.ReadFile(filepath.Join("..", "..", "config", "base", "crd", "bases", "connect.datumapis.com_"+plural+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(encoded, crd); err != nil {
			t.Fatal(err)
		}
		environment.CRDs = append(environment.CRDs, crd)
	}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = AddToScheme(scheme)
	project, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := project.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "service"}}); err != nil {
		t.Fatal(err)
	}
	gateway := &ConnectGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "service", Name: "shared"}, Spec: ConnectGatewaySpec{ContractVersion: "managed-network-v1", Placement: &ConnectGatewayPlacementPolicy{LocationSelector: metav1.LabelSelector{}}}}
	if err := project.Create(ctx, gateway); err != nil {
		t.Fatal("network-independent gateway rejected", err)
	}
	legacy := &ConnectGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "service", Name: "legacy"}, Spec: ConnectGatewaySpec{ContractVersion: "legacy-v1", GatewayClassRef: "class", LocationRef: "location", Routes: []string{"fd00::/48"}}}
	if err := project.Create(ctx, legacy); !apierrors.IsInvalid(err) {
		t.Fatal("legacy gateway lost required network scope", err)
	}
	binding := &ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "service", Name: "one"}, Spec: ConnectNetworkBindingSpec{GatewayRef: "shared", ConnectorRef: "laptop", NetworkRef: "one"}}
	if err := project.Create(ctx, binding); err != nil {
		t.Fatal(err)
	}
	binding.Spec.NetworkRef = "two"
	if err := project.Update(ctx, binding); !apierrors.IsInvalid(err) {
		t.Fatal("binding silently changed network scope", err)
	}
	endpoint := &ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Namespace: "service", Name: "reservation"}, Spec: ConnectEndpointSpec{CustomerProjectUID: "project-uid", GatewayUID: "gateway-uid", Metro: "dfw", Hostname: "reservation.example.test", CustomerProject: "customer", GatewayNamespace: "default", GatewayName: "gateway", Lifecycle: "Active"}}
	if err := project.Create(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	endpoint.Status = ConnectEndpointStatus{Phase: "Active", Ready: true, DeliveredSecrets: []string{"old-secret"}, DeliveryReceipts: []EndpointDeliveryReceipt{{APIVersion: "v1", Kind: "Secret", Namespace: "masque", Name: "old-secret", UID: "secret-uid", ContentDigest: "digest"}}}
	if err := project.Status().Update(ctx, endpoint); err != nil {
		t.Fatal("legacy migration state pruned or rejected", err)
	}
	if err := project.Get(ctx, client.ObjectKeyFromObject(endpoint), endpoint); err != nil || len(endpoint.Status.DeliveredSecrets) != 1 || endpoint.Status.DeliveryReceipts[0].UID != "secret-uid" {
		t.Fatal("schema lost durable legacy receipt", err)
	}
	endpoint.Status.Phase, endpoint.Status.Ready = "", false
	endpoint.Status.DeliveredSecrets = nil
	endpoint.Status.DeliveryReceipts[0].State = "Created"
	endpoint.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: "MigrationPending", Message: "verification required", LastTransitionTime: metav1.Now(), ObservedGeneration: endpoint.Generation}}
	if err := project.Status().Update(ctx, endpoint); err != nil {
		t.Fatal("condition/inventory migration rejected", err)
	}
	grant := &ConnectGrant{ObjectMeta: metav1.ObjectMeta{Namespace: "service", Name: "grant"}, Spec: ConnectGrantSpec{NetworkName: "network", NetworkUID: "network-uid", VPC: EndpointVPCReference{Namespace: "vpcs", Name: "network", UID: "vpc-uid"}, EndpointName: endpoint.Name, EndpointUID: string(endpoint.UID), BindingName: "one", BindingUID: "binding-uid", PolicyRevision: "policy", ConnectorID: "connector", Cell: "cell"}}
	if err := project.Create(ctx, grant); err != nil {
		t.Fatal(err)
	}
	grant.Status.Retiring = true
	if err := project.Status().Update(ctx, grant); err != nil {
		t.Fatal(err)
	}
	grant.Status = ConnectGrantStatus{State: "Retiring"}
	if err := project.Status().Update(ctx, grant); err != nil {
		t.Fatal("legacy revocation conversion rejected", err)
	}
	invalid := grant.DeepCopy()
	invalid.Status.State = "Active"
	if err := project.Status().Update(ctx, invalid); !apierrors.IsInvalid(err) {
		t.Fatal("retiring grant reactivated", err)
	}
	grant.Status.State = "Retired"
	if err := project.Status().Update(ctx, grant); err != nil {
		t.Fatal(err)
	}
	invalid = grant.DeepCopy()
	invalid.Status.State = "Retiring"
	if err := project.Status().Update(ctx, invalid); !apierrors.IsInvalid(err) {
		t.Fatal("retired grant tombstone reset", err)
	}
	invalid = grant.DeepCopy()
	invalid.Status = ConnectGrantStatus{}
	if err := project.Status().Update(ctx, invalid); !apierrors.IsInvalid(err) {
		t.Fatal("retired grant state erased", err)
	}
	endpoint.Spec.Assignment = EndpointAssignment{Cell: "cell", Provider: "provider", Frontend: "cell.example.test"}
	if err := project.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ConnectEndpoint){"identity": func(value *ConnectEndpoint) { value.Spec.GatewayUID = "other" }, "cell": func(value *ConnectEndpoint) { value.Spec.Assignment.Cell = "other" }, "hostname": func(value *ConnectEndpoint) { value.Spec.Hostname = "other.example.test" }} {
		t.Run(name, func(t *testing.T) {
			modified := endpoint.DeepCopy()
			mutate(modified)
			if err := project.Update(ctx, modified); !apierrors.IsInvalid(err) {
				t.Fatal("immutable identity accepted", err)
			}
		})
	}
	endpoint.Spec.Lifecycle = "Deleting"
	if err := project.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	endpoint.Spec.Lifecycle = "Active"
	if err := project.Update(ctx, endpoint); !apierrors.IsInvalid(err) {
		t.Fatal("resurrection accepted", err)
	}
}
