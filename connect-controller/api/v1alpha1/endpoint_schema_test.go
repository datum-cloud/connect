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
	for _, plural := range []string{"connectendpoints", "connectgrants"} {
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
	endpoint := &ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Namespace: "service", Name: "reservation"}, Spec: ConnectEndpointSpec{CustomerProjectUID: "project-uid", GatewayUID: "gateway-uid", Metro: "dfw", Hostname: "reservation.example.test", CustomerProject: "customer", GatewayNamespace: "default", GatewayName: "gateway", NetworkUID: "network-uid", Lifecycle: "Active"}}
	if err := project.Create(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	endpoint.Spec.Assignment = EndpointAssignment{Cell: "cell", Provider: "provider", Frontend: "cell.example.test", VPC: EndpointVPCReference{Namespace: "vpc", Name: "network", UID: "vpc-uid"}}
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
