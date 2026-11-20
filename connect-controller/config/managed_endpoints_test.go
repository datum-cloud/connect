package config_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedEndpointRuntimeIsOptIn(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl is required for component validation")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	overlay := t.TempDir()
	overlay, err = filepath.EvalSymlinks(overlay)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(overlay, root)
	if err != nil {
		t.Fatal(err)
	}
	manifest := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- " + filepath.Join(relative, "base/manager") + "\ncomponents:\n- " + filepath.Join(relative, "components/managed-endpoints/runtime") + "\n"
	if err := os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	managed, err := exec.Command("kubectl", "kustomize", overlay).CombinedOutput()
	if err != nil {
		t.Fatalf("runtime component: %v: %s", err, managed)
	}
	base, err := exec.Command("kubectl", "kustomize", "base/manager").CombinedOutput()
	if err != nil {
		t.Fatalf("manager base: %v: %s", err, base)
	}
	for _, value := range []string{"/etc/connect/endpoint-project", "/etc/connect/endpoint-project-client", "/etc/connect/karmada", "/etc/connect/certificates", "/var/run/secrets/connect-karmada", "/etc/connect/cells", "/etc/connect/endpoints", "https://karmada-apiserver.karmada-system.svc.cluster.local:5443"} {
		if !strings.Contains(string(managed), value) || strings.Contains(string(base), value) {
			t.Fatalf("managed mount is missing or enabled by default: %s", value)
		}
	}
	if strings.Contains(string(managed), "--managed-endpoints") || strings.Contains(string(managed), "kind: Role") {
		t.Fatal("runtime component must not enable flags or grant permissions")
	}
}

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
