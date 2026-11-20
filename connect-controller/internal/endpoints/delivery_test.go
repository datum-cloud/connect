package endpoints

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDeliveryUsesPrivateIncarnationReceipts(t *testing.T) {
	ctx := context.Background()
	endpoint := endpointFixture()
	project := resourceClient(t, endpoint)
	karmada := resourceClient(t)
	driver := &KubernetesDriver{Project: project, Karmada: karmada}
	desired := object(registrationGVK, "masque", endpoint.Name)
	desired.Object["spec"] = map[string]interface{}{"hostname": endpoint.Spec.Hostname, "cell": "cell-a", "provider": "shared", "metro": "dfw", "revision": int64(1), "enabled": true}
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
