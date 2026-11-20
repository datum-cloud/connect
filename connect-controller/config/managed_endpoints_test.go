package config_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestManagedEndpointCRDsAreServiceProjectOnly(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl is required for export validation")
	}
	managed, err := exec.Command("kubectl", "kustomize", "components/managed-endpoints/crd").CombinedOutput()
	if err != nil {
		t.Fatalf("managed export: %v: %s", err, managed)
	}
	customer, err := exec.Command("kubectl", "kustomize", "default").CombinedOutput()
	if err != nil {
		t.Fatalf("customer export: %v: %s", err, customer)
	}
	for _, resource := range []string{"connectendpoints.connect.datumapis.com", "connectgrants.connect.datumapis.com"} {
		if !strings.Contains(string(managed), "name: "+resource) || strings.Contains(string(customer), "name: "+resource) {
			t.Fatalf("%s has wrong project scope", resource)
		}
	}
	if strings.Contains(string(managed), "discovery.miloapis.com/parent-contexts") || strings.Count(string(managed), "kind: CustomResourceDefinition") != 2 {
		t.Fatal("service-only export contains customer discovery or unrelated APIs")
	}
}
