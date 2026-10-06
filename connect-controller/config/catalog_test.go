package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

type catalogObject struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		ServiceName string `json:"serviceName"`
		ServiceRef  struct {
			Name string `json:"name"`
		} `json:"serviceRef"`
	} `json:"spec"`
}

func readCatalogObject(t *testing.T, path string) catalogObject {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var object catalogObject
	if err := yaml.Unmarshal(contents, &object); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return object
}

func TestServiceCatalogReferencesUseResourceNames(t *testing.T) {
	service := readCatalogObject(t, "components/service-catalog/service.yaml")
	if errors := validation.IsDNS1123Label(service.Metadata.Name); len(errors) != 0 {
		t.Fatalf("Service metadata.name %q is not a DNS label: %v", service.Metadata.Name, errors)
	}
	if service.Spec.ServiceName != "connect.datumapis.com" {
		t.Fatalf("Service spec.serviceName = %q, want API service name connect.datumapis.com", service.Spec.ServiceName)
	}

	configuration := readCatalogObject(t, "components/service-catalog/service-configuration.yaml")
	if errors := validation.IsDNS1123Label(configuration.Metadata.Name); len(errors) != 0 {
		t.Fatalf("ServiceConfiguration metadata.name %q is not a DNS label: %v", configuration.Metadata.Name, errors)
	}
	if configuration.Spec.ServiceRef.Name != service.Metadata.Name {
		t.Fatalf("ServiceConfiguration serviceRef %q does not reference Service %q", configuration.Spec.ServiceRef.Name, service.Metadata.Name)
	}

	protectedResources, err := filepath.Glob("components/iam/protected-resources/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(protectedResources) == 0 {
		t.Fatal("no ProtectedResource manifests found")
	}
	for _, path := range protectedResources {
		resource := readCatalogObject(t, path)
		if resource.Spec.ServiceRef.Name != service.Metadata.Name {
			t.Errorf("%s serviceRef %q does not reference Service %q", path, resource.Spec.ServiceRef.Name, service.Metadata.Name)
		}
	}
}
