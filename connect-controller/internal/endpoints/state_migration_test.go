package endpoints

import (
	"context"
	"testing"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestLegacyReadinessNeverAuthorizesWithoutFreshCondition(t *testing.T) {
	now := time.Now()
	endpoint := endpointFixture()
	endpoint.Generation = 3
	endpoint.Status.Phase = "Active"
	endpoint.Status.Ready = true
	endpoint.Status.CertificateRevision = "revision"
	expires, verified := metav1.NewTime(now.Add(time.Hour)), metav1.NewTime(now)
	endpoint.Status.NotAfter, endpoint.Status.VerifiedAt = &expires, &verified
	endpoint.Status.Revision = 2
	if Ready(endpoint, now, time.Minute) {
		t.Fatal("legacy readiness authorized without condition")
	}
	setReady(endpoint, true, "Ready")
	if !Ready(endpoint, now, time.Minute) || endpoint.Status.Phase != "" || endpoint.Status.Ready || endpoint.Status.Reason != "" {
		t.Fatal("condition transition did not clear legacy state")
	}
	endpoint.Generation++
	if Ready(endpoint, now, time.Minute) {
		t.Fatal("stale condition authorized new generation")
	}
}

func TestInventoryMigrationPreservesUncertainCreatesAndRemoval(t *testing.T) {
	ctx := context.Background()
	endpoint := endpointFixture()
	endpoint.Status.DeliveredSecrets = []string{"old", "planned"}
	endpoint.Status.DeliveryReceipts = []connect.EndpointDeliveryReceipt{{APIVersion: "v1", Kind: "Secret", Namespace: "masque", Name: "old", UID: "old-uid", ContentDigest: "kept"}}
	project := resourceClient(t, endpoint)
	karmada, selected := resourceClient(t), resourceClient(t)
	driver := &KubernetesDriver{Project: project, Karmada: karmada, RuntimeNamespace: "masque", Cells: map[string]client.Client{endpoint.Spec.Assignment.Cell: selected}}
	if err := driver.migrateInventory(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if len(endpoint.Status.DeliveredSecrets) != 0 || len(endpoint.Status.DeliveryReceipts) != 2 || endpoint.Status.DeliveryReceipts[0].State != "Created" || endpoint.Status.DeliveryReceipts[0].ContentDigest != "kept" {
		t.Fatal("migration lost recorded inventory")
	}
	planned := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "masque", Name: "planned"}, Data: map[string][]byte{"key": []byte("bytes")}}
	if err := karmada.Create(ctx, planned); err != nil {
		t.Fatal(err)
	}
	if err := driver.rememberDelivery(ctx, endpoint, planned); err == nil {
		t.Fatal("name-only migration adopted unproven object")
	}
	if err := karmada.Delete(ctx, planned); err != nil {
		t.Fatal(err)
	}
	if err := driver.prepareDelivery(ctx, endpoint, planned); err != nil {
		t.Fatal(err)
	}
	planned.SetResourceVersion("")
	planned.SetUID("")
	if err := karmada.Create(ctx, planned); err != nil {
		t.Fatal(err)
	}
	if err := driver.rememberDelivery(ctx, endpoint, planned); err != nil {
		t.Fatal("lost create response could not bind exact planned digest", err)
	}
	if done, err := driver.removeSecret(ctx, endpoint, "planned"); err != nil || done {
		t.Fatal("deletion must wait for observed absence", err)
	}
	if done, err := driver.removeSecret(ctx, endpoint, "planned"); err != nil || !done {
		t.Fatal("confirmed deletion not recorded", err)
	}
	if receipt := deliveryReceipt(endpoint, planned); receipt.State != "Removed" || receipt.UID == "" || receipt.ContentDigest == "" || len(endpoint.Status.DeliveryReceipts) != 2 {
		t.Fatal("cleanup erased durable evidence")
	}
	driver.RuntimeNamespace = "other-runtime"
	if err := driver.migrateInventory(ctx, endpoint); err == nil {
		t.Fatal("configuration drift silently ignored recorded delivery scope")
	}
}
