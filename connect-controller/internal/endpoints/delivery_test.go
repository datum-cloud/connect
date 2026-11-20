package endpoints

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDeliveryUsesPrivateIncarnationReceipts(t *testing.T) {
	ctx := context.Background()
	endpoint := endpointFixture()
	project := resourceClient(t, endpoint)
	karmada := resourceClient(t)
	driver := &KubernetesDriver{Project: project, Karmada: karmada}
	desired := object(registrationGVK, "masque", endpoint.Name)
	desired.Object["spec"] = map[string]interface{}{"hostname": endpoint.Spec.Hostname, "provider": "shared", "revision": int64(1), "enabled": true}
	if err := karmada.Create(ctx, desired); err != nil {
		t.Fatal(err)
	}
	if err := driver.ensureDelivery(ctx, endpoint, desired); err != nil {
		t.Fatal("exact adoption after uncertain create failed", err)
	}
	if len(endpoint.Status.DeliveryReceipts) != 1 || endpoint.Status.DeliveryReceipts[0].UID != string(desired.GetUID()) {
		t.Fatal("private receipt missing")
	}
	if err := karmada.Get(ctx, client.ObjectKeyFromObject(desired), desired); err != nil {
		t.Fatal(err)
	}
	if len(desired.GetLabels()) != 0 || len(desired.GetAnnotations()) != 0 {
		t.Fatal("identity leaked into delivered metadata")
	}
	if err := karmada.Delete(ctx, desired); err != nil {
		t.Fatal(err)
	}
	desired.SetResourceVersion("")
	desired.SetUID("replacement")
	if err := karmada.Create(ctx, desired); err != nil {
		t.Fatal(err)
	}
	if err := driver.ensureDelivery(ctx, endpoint, desired); err == nil {
		t.Fatal("replaced registration adopted")
	}
	if _, err := driver.removeDeliveryResource(ctx, endpoint, desired); err == nil {
		t.Fatal("replaced registration deleted")
	}
}

func TestPlacementRemovalPreservesDeliveryReceiptAndRevision(t *testing.T) {
	ctx := context.Background()
	endpoint := endpointFixture()
	karmada := resourceClient(t)
	driver := &KubernetesDriver{Project: resourceClient(t, endpoint), Karmada: karmada}
	current := object(registrationGVK, "masque", endpoint.Name)
	current.Object["spec"] = map[string]interface{}{"hostname": endpoint.Spec.Hostname, "provider": "shared", "cell": "cell-a", "metro": "dfw", "revision": int64(1), "enabled": true}
	if err := karmada.Create(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := driver.rememberDelivery(ctx, endpoint, current); err != nil {
		t.Fatal(err)
	}
	desired := current.DeepCopy()
	unstructured.RemoveNestedField(desired.Object, "spec", "cell")
	unstructured.RemoveNestedField(desired.Object, "spec", "metro")
	if err := driver.ensureDelivery(ctx, endpoint, desired); err == nil {
		t.Fatal("changed same-revision snapshot accepted")
	}
	_ = unstructured.SetNestedField(desired.Object, int64(2), "spec", "revision")
	_ = unstructured.SetNestedField(desired.Object, false, "spec", "enabled")
	if err := driver.ensureDelivery(ctx, endpoint, desired); err != nil {
		t.Fatal("higher revision local update rejected", err)
	}
	if receipt := deliveryReceipt(endpoint, desired); receipt == nil || receipt.UID != string(current.GetUID()) || len(endpoint.Status.DeliveryReceipts) != 1 {
		t.Fatal("placement removal reset the private incarnation receipt")
	}
	if err := karmada.Get(ctx, client.ObjectKeyFromObject(current), current); err != nil {
		t.Fatal(err)
	}
	if revision, _, _ := unstructured.NestedInt64(current.Object, "spec", "revision"); revision != 2 {
		t.Fatal("registration revision lost")
	}
	for _, field := range []string{"cell", "metro"} {
		if _, exists, _ := unstructured.NestedFieldNoCopy(current.Object, "spec", field); exists {
			t.Fatal("placement copied into local registration", field)
		}
	}
}

func TestUnrecordedDeliveryRequiresExactContent(t *testing.T) {
	ctx := context.Background()
	endpoint := endpointFixture()
	endpoint.Status.CertificateRevision = strings.Repeat("a", 64)
	project := resourceClient(t, endpoint)
	karmada := resourceClient(t)
	driver := &KubernetesDriver{Project: project, Karmada: karmada}
	secret := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Namespace: "masque", Name: SecretName(endpoint), Annotations: map[string]string{"masque.galactic.datumapis.com/certificate-revision": endpoint.Status.CertificateRevision}}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": []byte("expected"), "tls.key": []byte("private")}}
	foreign := secret.DeepCopy()
	foreign.Data["tls.key"] = []byte("different")
	if err := karmada.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	if err := driver.ensureDeliverySecret(ctx, endpoint, secret); err == nil {
		t.Fatal("different key adopted")
	}
	if _, err := driver.removeDeliveryResource(ctx, endpoint, foreign); err == nil {
		t.Fatal("unrecorded Secret deleted")
	}
	registration := object(registrationGVK, "masque", endpoint.Name)
	registration.Object["spec"] = map[string]interface{}{"hostname": "other.example.test", "revision": int64(1)}
	if err := karmada.Create(ctx, registration); err != nil {
		t.Fatal(err)
	}
	desired := registration.DeepCopy()
	desired.Object["spec"] = map[string]interface{}{"hostname": endpoint.Spec.Hostname, "revision": int64(2)}
	if err := driver.ensureDelivery(ctx, endpoint, desired); err == nil {
		t.Fatal("foreign hostname adopted")
	}
}

func TestCleanupRecoversCreateBeforeReceiptBinding(t *testing.T) {
	ctx := context.Background()
	endpoint := endpointFixture()
	project := resourceClient(t, endpoint)
	karmada := resourceClient(t)
	driver := &KubernetesDriver{Project: project, Karmada: karmada}
	registration := object(registrationGVK, "masque", endpoint.Name)
	registration.Object["spec"] = map[string]interface{}{"hostname": endpoint.Spec.Hostname, "revision": int64(1), "enabled": false}
	if err := driver.prepareDelivery(ctx, endpoint, registration); err != nil {
		t.Fatal(err)
	}
	if err := karmada.Create(ctx, registration); err != nil {
		t.Fatal(err)
	}
	if err := project.Get(ctx, client.ObjectKeyFromObject(endpoint), endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.Status.DeliveryReceipts[0].UID != "" {
		t.Fatal("fixture must interrupt before receipt binding")
	}
	if _, err := driver.removeDeliveryResource(ctx, endpoint, registration); err != nil {
		t.Fatal("durable intent failed to recover interrupted create", err)
	}
	if done, err := driver.removeDeliveryResource(ctx, endpoint, registration); err != nil || !done {
		t.Fatal("cleanup not complete", err)
	}
}

func TestLegacyDistributedIdentityRequiresMigration(t *testing.T) {
	ctx := context.Background()
	for _, annotation := range []bool{false, true} {
		endpoint := endpointFixture()
		project := resourceClient(t, endpoint)
		registration := object(registrationGVK, "masque", endpoint.Name)
		registration.SetUID("old-registration")
		registration.Object["spec"] = map[string]interface{}{"hostname": endpoint.Spec.Hostname, "revision": int64(1)}
		if annotation {
			registration.SetAnnotations(map[string]string{"masque.galactic.datumapis.com/endpoint-uid": string(endpoint.UID)})
		} else {
			registration.SetLabels(map[string]string{OwnerLabel: string(endpoint.UID)})
		}
		karmada := resourceClient(t, registration)
		driver := &KubernetesDriver{Project: project, Karmada: karmada}
		desired := registration.DeepCopy()
		desired.SetLabels(nil)
		desired.SetAnnotations(nil)
		if err := driver.ensureDelivery(ctx, endpoint, desired); err == nil {
			t.Fatal("legacy UID-bearing delivery silently adopted")
		}
		if len(endpoint.Status.DeliveryReceipts) != 0 {
			t.Fatal("legacy delivery acquired a cleanup receipt")
		}
	}
}
