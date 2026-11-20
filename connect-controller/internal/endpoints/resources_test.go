package endpoints

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func tlsFixture(t *testing.T, hostname string, now time.Time) (*corev1.Secret, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{hostname}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return &corev1.Secret{Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}}, hex.EncodeToString(sum[:])
}

func TestCertificateConsumerRejectsInvalidMaterial(t *testing.T) {
	now := time.Now()
	secret, revision := tlsFixture(t, "gateway.example.test", now)
	if _, err := ValidateCertificate(secret, "gateway.example.test", revision, now); err != nil {
		t.Fatal(err)
	}
	other, _ := tlsFixture(t, "gateway.example.test", now)
	for name, check := range map[string]func() error{
		"name": func() error { _, err := ValidateCertificate(secret, "other.example.test", revision, now); return err },
		"revision": func() error {
			_, err := ValidateCertificate(secret, "gateway.example.test", strings.Repeat("0", 64), now)
			return err
		},
		"expired": func() error {
			_, err := ValidateCertificate(secret, "gateway.example.test", revision, now.Add(2*time.Hour))
			return err
		},
		"future": func() error {
			_, err := ValidateCertificate(secret, "gateway.example.test", revision, now.Add(-2*time.Hour))
			return err
		},
		"key": func() error {
			wrong := secret.DeepCopy()
			wrong.Data[corev1.TLSPrivateKeyKey] = other.Data[corev1.TLSPrivateKeyKey]
			_, err := ValidateCertificate(wrong, "gateway.example.test", revision, now)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if check() == nil {
				t.Fatal("invalid material accepted")
			}
		})
	}
}

func resourceClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = coordinationv1.AddToScheme(scheme)
	_ = connect.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(schema.GroupVersionKind{Group: registrationGVK.Group, Version: registrationGVK.Version, Kind: "EdgeInstanceList"}, &unstructured.UnstructuredList{})
	return fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&connect.ConnectEndpoint{}, &connect.ConnectGrant{}, &connect.ConnectGatewayPlacement{}).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, target client.WithWatch, resource client.Object, options ...client.CreateOption) error {
		if resource.GetUID() == "" {
			resource.SetUID(types.UID("created-" + resource.GetName()))
		}
		return target.Create(ctx, resource, options...)
	}}).Build()
}

func TestExactDNS01AndSeparateKeyCustody(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	endpoint := endpointFixture()
	endpoint.Status.Phase = "Active"
	endpoint.Status.CertificateRef = connect.EndpointCertificateReference{Name: endpoint.Name, UID: "certificate-uid"}
	stored, revision := tlsFixture(t, endpoint.Spec.Hostname, now)
	sum := sha256.Sum256([]byte("certificate-uid"))
	stored.Name = "tc-" + hex.EncodeToString(sum[:16])
	stored.Namespace = "certificates"
	stored.Labels = map[string]string{"certificates.miloapis.com/upstream-uid": "certificate-uid"}
	request := object(certificateGVK, endpoint.Namespace, endpoint.Name)
	request.SetUID("certificate-uid")
	request.SetLabels(map[string]string{OwnerLabel: string(endpoint.UID)})
	request.Object["spec"] = map[string]interface{}{"issuance": "DNS01", "dnsNames": []interface{}{endpoint.Spec.Hostname}, "managedAuthorization": map[string]interface{}{"reservationName": endpoint.Name, "reservationUID": string(endpoint.UID)}}
	target := "random-token.delegation.example.test."
	request.Object["status"] = map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": "Ready", "status": "True", "observedGeneration": int64(0)}}, "certificateRevision": revision, "requiredDNSRecords": []interface{}{map[string]interface{}{"name": "_acme-challenge." + endpoint.Spec.Hostname + ".", "type": "CNAME", "content": target}}}
	zone := object(schema.GroupVersionKind{Group: recordGVK.Group, Version: recordGVK.Version, Kind: "DNSZone"}, endpoint.Namespace, "shared")
	zone.Object["spec"] = map[string]interface{}{"domainName": "connect.example.test"}
	project := resourceClient(t, endpoint, request, zone)
	karmada := resourceClient(t)
	certificates := resourceClient(t, stored)
	driver := &KubernetesDriver{Project: project, Karmada: karmada, Certificates: certificates, CertificateNamespace: "certificates", RuntimeNamespace: "masque", Domain: "connect.example.test", Zone: "shared", Now: func() time.Time { return now }}
	certificate, err := driver.Certificate(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Revision != revision {
		t.Fatal(certificate)
	}
	record := object(recordGVK, endpoint.Namespace, endpoint.Name+"-challenge")
	if err := project.Get(ctx, client.ObjectKeyFromObject(record), record); err != nil {
		t.Fatal(err)
	}
	records, _, _ := unstructured.NestedSlice(record.Object, "spec", "records")
	if records[0].(map[string]interface{})["cname"].(map[string]interface{})["content"] != target {
		t.Fatal("challenge delegation target changed")
	}
	endpoint.Status.CertificateRevision = revision
	endpoint.Status.Revision = 1
	endpoint.Status.DeliveredSecrets = []string{SecretName(endpoint)}
	if err := project.Status().Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := driver.Apply(ctx, endpoint, true); err != nil {
		t.Fatal(err)
	}
	var projectSecrets corev1.SecretList
	if err := project.List(ctx, &projectSecrets); err != nil {
		t.Fatal(err)
	}
	if len(projectSecrets.Items) != 0 {
		t.Fatal("private key entered service project")
	}
	delivered := &corev1.Secret{}
	if err := karmada.Get(ctx, client.ObjectKey{Namespace: "masque", Name: SecretName(endpoint)}, delivered); err != nil {
		t.Fatal(err)
	}
	if delivered.Annotations["masque.galactic.datumapis.com/certificate-revision"] != revision {
		t.Fatal("missing Galactic certificate revision annotation")
	}
	policy := object(policyGVK, "masque", endpoint.Name)
	if err := karmada.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	clusters, _, _ := unstructured.NestedStringSlice(policy.Object, "spec", "placement", "clusterAffinity", "clusterNames")
	if len(clusters) != 1 || clusters[0] != "cell-a" {
		t.Fatal("multi-cell delivery", clusters)
	}
	cell, applied := membershipFixture(t, endpoint, now)
	desired := object(registrationGVK, "masque", endpoint.Name)
	if err := karmada.Get(ctx, client.ObjectKeyFromObject(desired), desired); err != nil {
		t.Fatal(err)
	}
	if spec, _, err := unstructured.NestedMap(desired.Object, "spec"); err != nil || len(spec) != 5 {
		t.Fatal("registration does not match five-field local contract", spec, err)
	}
	for _, field := range []string{"endpointUID", "customerProjectUID", "gatewayUID", "networkUID", "vpcRef", "cell", "metro"} {
		if _, exists, err := unstructured.NestedFieldNoCopy(desired.Object, "spec", field); err != nil || exists {
			t.Fatalf("removed registration field delivered: %s", field)
		}
	}
	for _, resource := range []client.Object{desired, delivered, policy} {
		if resource.GetLabels()[OwnerLabel] != "" || resource.GetAnnotations()["masque.galactic.datumapis.com/endpoint-uid"] != "" {
			t.Fatal("identity UID leaked into distributed metadata")
		}
		if receipt := deliveryReceipt(endpoint, resource); receipt == nil || receipt.UID != string(resource.GetUID()) {
			t.Fatal("distributed resource has no private incarnation receipt")
		}
	}
	applied.Object["spec"] = desired.Object["spec"]
	if err := cell.Update(ctx, applied); err != nil {
		t.Fatal(err)
	}
	driver.Cells = map[string]client.Client{"cell-a": cell}
	expires := metav1.NewTime(certificate.NotAfter)
	endpoint.Status.NotAfter = &expires
	if err := project.Status().Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	reconciler := &Reconciler{Project: project, Driver: driver, Now: driver.Now, ExpiryMargin: 5 * time.Minute}
	if err := reconciler.Reconcile(ctx, client.ObjectKeyFromObject(endpoint)); err == nil {
		t.Fatal("delivery and acks without external probe became Ready")
	}
	driver.ProbeEndpoint = func(context.Context, *connect.ConnectEndpoint) error { return nil }
	if err := reconciler.Reconcile(ctx, client.ObjectKeyFromObject(endpoint)); err != nil {
		t.Fatal(err)
	}
	if err := project.Get(ctx, client.ObjectKeyFromObject(endpoint), endpoint); err != nil {
		t.Fatal(err)
	}
	if !Ready(endpoint, now, 5*time.Minute) {
		t.Fatal("complete resource lifecycle did not become Ready")
	}
	route := object(recordGVK, endpoint.Namespace, endpoint.Name+"-route")
	if err := project.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
		t.Fatal(err)
	}
	endpoint.Spec.Lifecycle = "Deleting"
	if err := project.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := driver.Apply(ctx, endpoint, true); err == nil {
		t.Fatal("stale worker enabled retired endpoint")
	}
	stored.Labels["certificates.miloapis.com/upstream-uid"] = "foreign"
	if err := certificates.Update(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Certificate(ctx, endpoint); err == nil {
		t.Fatal("foreign stored Secret accepted")
	}
}

func membershipFixture(t *testing.T, endpoint *connect.ConnectEndpoint, now time.Time) (client.Client, *unstructured.Unstructured) {
	t.Helper()
	registration := object(registrationGVK, "masque", endpoint.Name)
	registration.Object["spec"] = map[string]interface{}{"revision": endpoint.Status.Revision, "hostname": endpoint.Spec.Hostname, "provider": endpoint.Spec.Assignment.Provider, "enabled": true, "certificateRef": map[string]interface{}{"revision": endpoint.Status.CertificateRevision}}
	_ = unstructured.SetNestedField(registration.Object, SecretName(endpoint), "spec", "certificateRef", "name")
	registration.Object["status"] = map[string]interface{}{"instances": []interface{}{map[string]interface{}{"instanceName": "ei-pod-a", "observedRevision": endpoint.Status.Revision, "appliedRevision": endpoint.Status.Revision, "appliedCertificateRevision": endpoint.Status.CertificateRevision, "state": "Applied", "forwardingStopped": false, "lastHeartbeatTime": now.Format(time.RFC3339)}}}
	instance := object(schema.GroupVersionKind{Group: registrationGVK.Group, Version: registrationGVK.Version, Kind: "EdgeInstance"}, "masque", "ei-pod-a")
	instance.SetUID("instance-a")
	instance.SetCreationTimestamp(metav1.NewTime(now.Add(-time.Minute)))
	instance.Object["spec"] = map[string]interface{}{"providerRef": map[string]interface{}{"name": "shared"}, "podUID": "pod-a"}
	holder := "pod-a"
	duration := int32(30)
	renew := metav1.NewMicroTime(now)
	acquired := metav1.NewMicroTime(now.Add(-30 * time.Second))
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: instance.GetName(), Namespace: "masque", UID: "lease-a", Annotations: map[string]string{"galactic.datumapis.com/edge-pod-uid": "pod-a"}, OwnerReferences: []metav1.OwnerReference{{Kind: "EdgeInstance", UID: instance.GetUID()}}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &renew, AcquireTime: &acquired}}
	return resourceClient(t, registration, instance, lease), registration
}

func TestAcknowledgmentsStayInSelectedControlPlane(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, enabled := range []bool{true, false} {
		state := "apply"
		if !enabled {
			state = "stop"
		}
		t.Run(state, func(t *testing.T) {
			endpoint := endpointFixture()
			endpoint.Status.Revision = 4
			endpoint.Status.CertificateRevision = strings.Repeat("a", 64)
			selected, registration := membershipFixture(t, endpoint, now)
			other, otherRegistration := membershipFixture(t, endpoint, now)
			if !enabled {
				for _, fixture := range []struct {
					target   client.Client
					resource *unstructured.Unstructured
				}{{selected, registration}, {other, otherRegistration}} {
					resource := fixture.resource
					_ = unstructured.SetNestedField(resource.Object, false, "spec", "enabled")
					entries, _, _ := unstructured.NestedSlice(resource.Object, "status", "instances")
					entries[0].(map[string]interface{})["state"] = "Disabled"
					entries[0].(map[string]interface{})["forwardingStopped"] = true
					_ = unstructured.SetNestedSlice(resource.Object, entries, "status", "instances")
					if err := fixture.target.Update(ctx, resource); err != nil {
						t.Fatal(err)
					}
				}
			}
			driver := &KubernetesDriver{Cells: map[string]client.Client{"cell-a": selected, "cell-b": other}, RuntimeNamespace: "masque", Now: func() time.Time { return now }}
			if err := driver.Applied(ctx, endpoint, enabled); err != nil {
				t.Fatal(err)
			}
			_ = unstructured.SetNestedSlice(registration.Object, nil, "status", "instances")
			if err := selected.Update(ctx, registration); err != nil {
				t.Fatal(err)
			}
			if err := driver.Applied(ctx, endpoint, enabled); err == nil {
				t.Fatal("identically named acknowledgment from another control plane accepted")
			}
			driver.Cells["cell-a"] = resourceClient(t)
			if err := driver.Applied(ctx, endpoint, enabled); err == nil {
				t.Fatal("missing selected registration fell back to another control plane")
			}
			delete(driver.Cells, "cell-a")
			if err := driver.Applied(ctx, endpoint, enabled); err == nil {
				t.Fatal("unconfigured selected control plane accepted")
			}
		})
	}
}

func TestCleanupStaysInSelectedControlPlane(t *testing.T) {
	ctx := context.Background()
	endpoint := endpointFixture()
	registration := object(registrationGVK, "masque", endpoint.Name)
	selected := resourceClient(t, registration)
	other := resourceClient(t, registration.DeepCopy())
	driver := &KubernetesDriver{Karmada: resourceClient(t), Cells: map[string]client.Client{"cell-a": selected, "cell-b": other}, RuntimeNamespace: "masque"}
	if done, err := driver.RemoveDelivery(ctx, endpoint); err != nil || done {
		t.Fatalf("selected registration still exists: done=%v err=%v", done, err)
	}
	if err := other.Delete(ctx, registration); err != nil {
		t.Fatal(err)
	}
	if done, err := driver.RemoveDelivery(ctx, endpoint); err != nil || done {
		t.Fatalf("absence in another control plane completed cleanup: done=%v err=%v", done, err)
	}
	restored := registration.DeepCopy()
	restored.SetResourceVersion("")
	if err := other.Create(ctx, restored); err != nil {
		t.Fatal(err)
	}
	delete(driver.Cells, "cell-a")
	if done, err := driver.RemoveDelivery(ctx, endpoint); err == nil || done {
		t.Fatal("cleanup accepted unconfigured selected control plane")
	}
	driver.Cells["cell-a"] = selected
	if err := selected.Delete(ctx, registration); err != nil {
		t.Fatal(err)
	}
	if done, err := driver.RemoveDelivery(ctx, endpoint); err != nil || !done {
		t.Fatalf("unrelated registration affected selected cleanup: done=%v err=%v", done, err)
	}
	if err := other.Get(ctx, client.ObjectKeyFromObject(registration), registration); err != nil {
		t.Fatal("other control plane registration was removed", err)
	}
}

func TestReadinessUsesMembershipNotAckCount(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	endpoint := endpointFixture()
	endpoint.Status.Revision = 4
	endpoint.Status.CertificateRevision = strings.Repeat("a", 64)
	cell, registration := membershipFixture(t, endpoint, now)
	driver := &KubernetesDriver{Cells: map[string]client.Client{"cell-a": cell}, RuntimeNamespace: "masque", Now: func() time.Time { return now }}
	if err := driver.Applied(ctx, endpoint, true); err != nil {
		t.Fatal(err)
	}
	second := object(schema.GroupVersionKind{Group: registrationGVK.Group, Version: registrationGVK.Version, Kind: "EdgeInstance"}, "masque", "ei-pod-b")
	second.SetUID("instance-b")
	second.SetCreationTimestamp(metav1.NewTime(now.Add(-time.Minute)))
	second.Object["spec"] = map[string]interface{}{"providerRef": map[string]interface{}{"name": "other-provider"}, "podUID": "pod-b"}
	if err := cell.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := driver.Applied(ctx, endpoint, true); err != nil {
		t.Fatal("independently selected provider affected readiness", err)
	}
	_ = unstructured.SetNestedField(second.Object, "shared", "spec", "providerRef", "name")
	if err := cell.Update(ctx, second); err != nil {
		t.Fatal(err)
	}
	secondLease := &coordinationv1.Lease{}
	if err := cell.Get(ctx, client.ObjectKey{Namespace: "masque", Name: "ei-pod-a"}, secondLease); err != nil {
		t.Fatal(err)
	}
	secondLease.Name, secondLease.UID, secondLease.ResourceVersion = second.GetName(), "lease-b", ""
	secondLease.OwnerReferences[0].UID = second.GetUID()
	secondLease.Annotations["galactic.datumapis.com/edge-pod-uid"] = "pod-b"
	if err := cell.Create(ctx, secondLease); err != nil {
		t.Fatal(err)
	}
	if err := driver.Applied(ctx, endpoint, true); err == nil {
		t.Fatal("new replica without ack was ignored")
	}
	if err := cell.Delete(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := cell.Get(ctx, client.ObjectKeyFromObject(registration), registration); err != nil {
		t.Fatal(err)
	}
	entries, _, _ := unstructured.NestedSlice(registration.Object, "status", "instances")
	entries[0].(map[string]interface{})["appliedCertificateRevision"] = strings.Repeat("b", 64)
	_ = unstructured.SetNestedSlice(registration.Object, entries, "status", "instances")
	if err := cell.Update(ctx, registration); err != nil {
		t.Fatal(err)
	}
	if err := driver.Applied(ctx, endpoint, true); err == nil {
		t.Fatal("old certificate ack accepted")
	}
	entries[0].(map[string]interface{})["appliedCertificateRevision"] = endpoint.Status.CertificateRevision
	entries[0].(map[string]interface{})["state"] = "Disabled"
	_ = unstructured.SetNestedField(registration.Object, false, "spec", "enabled")
	entries[0].(map[string]interface{})["forwardingStopped"] = true
	_ = unstructured.SetNestedSlice(registration.Object, entries, "status", "instances")
	if err := cell.Update(ctx, registration); err != nil {
		t.Fatal(err)
	}
	if err := driver.Applied(ctx, endpoint, false); err != nil {
		t.Fatal(err)
	}
	second.SetResourceVersion("")
	if err := cell.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := driver.Applied(ctx, endpoint, false); err == nil {
		t.Fatal("second live replica without forwarding-stop ack was ignored")
	}
	if err := cell.Delete(ctx, second); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Second)
	if err := driver.Applied(ctx, endpoint, false); err == nil {
		t.Fatal("stale forwarding stop accepted")
	}
}

func TestReadinessRejectsAcknowledgmentsFromPreviousIncarnation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, scenario := range []string{"recreated-instance", "reacquired-lease", "missing-acquire-time", "equal-acquire-time", "future-acquire-time", "missing-creation-time"} {
		t.Run(scenario, func(t *testing.T) {
			endpoint := endpointFixture()
			endpoint.Status.Revision = 4
			endpoint.Status.CertificateRevision = strings.Repeat("a", 64)
			cell, registration := membershipFixture(t, endpoint, now)
			driver := &KubernetesDriver{Cells: map[string]client.Client{"cell-a": cell}, RuntimeNamespace: "masque", Now: func() time.Time { return now }}
			instance := object(schema.GroupVersionKind{Group: registrationGVK.Group, Version: registrationGVK.Version, Kind: "EdgeInstance"}, "masque", "ei-pod-a")
			if err := cell.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
				t.Fatal(err)
			}
			lease := &coordinationv1.Lease{}
			if err := cell.Get(ctx, client.ObjectKeyFromObject(instance), lease); err != nil {
				t.Fatal(err)
			}
			entries, _, _ := unstructured.NestedSlice(registration.Object, "status", "instances")
			entries[0].(map[string]interface{})["lastHeartbeatTime"] = now.Add(-2 * time.Second).Format(time.RFC3339)
			_ = unstructured.SetNestedSlice(registration.Object, entries, "status", "instances")
			if err := cell.Update(ctx, registration); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "recreated-instance":
				if err := cell.Delete(ctx, instance); err != nil {
					t.Fatal(err)
				}
				instance.SetResourceVersion("")
				instance.SetUID("new-instance")
				instance.SetCreationTimestamp(metav1.NewTime(now.Add(-time.Second)))
				if err := cell.Create(ctx, instance); err != nil {
					t.Fatal(err)
				}
				lease.OwnerReferences[0].UID = instance.GetUID()
			case "missing-creation-time":
				instance.SetCreationTimestamp(metav1.Time{})
				if err := cell.Update(ctx, instance); err != nil {
					t.Fatal(err)
				}
			case "missing-acquire-time":
				lease.Spec.AcquireTime = nil
			case "equal-acquire-time":
				acquired := metav1.NewMicroTime(now.Add(-2 * time.Second))
				lease.Spec.AcquireTime = &acquired
			case "future-acquire-time":
				acquired := metav1.NewMicroTime(now.Add(time.Second))
				lease.Spec.AcquireTime = &acquired
			case "reacquired-lease":
				acquired := metav1.NewMicroTime(now.Add(-time.Second))
				lease.Spec.AcquireTime = &acquired
			}
			if err := cell.Update(ctx, lease); err != nil {
				t.Fatal(err)
			}
			if err := driver.Applied(ctx, endpoint, true); err == nil {
				t.Fatal("previous incarnation acknowledgment accepted")
			}
		})
	}
}
