package endpoints

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func deliveryDigest(resource client.Object) (string, error) {
	var content interface{}
	switch value := resource.(type) {
	case *corev1.Secret:
		content = struct {
			Type     corev1.SecretType
			Data     map[string][]byte
			Revision string
		}{value.Type, value.Data, value.Annotations["masque.galactic.datumapis.com/certificate-revision"]}
	case *unstructured.Unstructured:
		content = value.Object["spec"]
	default:
		return "", fmt.Errorf("unsupported delivery resource")
	}
	encoded, err := json.Marshal(content)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (d *KubernetesDriver) prepareDelivery(ctx context.Context, endpoint *connect.ConnectEndpoint, desired client.Object) error {
	digest, err := deliveryDigest(desired)
	if err != nil {
		return err
	}
	if receipt := deliveryReceipt(endpoint, desired); receipt != nil {
		if receipt.State == "Removed" {
			return d.appendPlannedDelivery(ctx, endpoint, desired, digest)
		}
		if receipt.UID == "" && receipt.ContentDigest == "" {
			receipt.ContentDigest = digest
			receipt.State = "Planned"
			return d.Project.Status().Update(ctx, endpoint)
		}
		if receipt.UID != "" || receipt.ContentDigest != digest {
			return fmt.Errorf("recorded delivery disappeared or pending content changed")
		}
		return nil
	}
	return d.appendPlannedDelivery(ctx, endpoint, desired, digest)
}

func (d *KubernetesDriver) appendPlannedDelivery(ctx context.Context, endpoint *connect.ConnectEndpoint, desired client.Object, digest string) error {
	gvk := deliveryGVK(desired)
	endpoint.Status.DeliveryReceipts = append(endpoint.Status.DeliveryReceipts, connect.EndpointDeliveryReceipt{State: "Planned", APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Namespace: desired.GetNamespace(), Name: desired.GetName(), ContentDigest: digest})
	return d.Project.Status().Update(ctx, endpoint)
}

func deliveryGVK(resource client.Object) schema.GroupVersionKind {
	if _, secret := resource.(*corev1.Secret); secret {
		return corev1.SchemeGroupVersion.WithKind("Secret")
	}
	return resource.GetObjectKind().GroupVersionKind()
}

func deliveryReceipt(endpoint *connect.ConnectEndpoint, resource client.Object) *connect.EndpointDeliveryReceipt {
	gvk := deliveryGVK(resource)
	for index := len(endpoint.Status.DeliveryReceipts) - 1; index >= 0; index-- {
		receipt := &endpoint.Status.DeliveryReceipts[index]
		if receipt.APIVersion == gvk.GroupVersion().String() && receipt.Kind == gvk.Kind && receipt.Namespace == resource.GetNamespace() && receipt.Name == resource.GetName() {
			return receipt
		}
	}
	return nil
}

func (d *KubernetesDriver) rememberDelivery(ctx context.Context, endpoint *connect.ConnectEndpoint, resource client.Object) error {
	if resource.GetUID() == "" || resource.GetDeletionTimestamp() != nil {
		return fmt.Errorf("delivery has no live incarnation")
	}
	if resource.GetLabels()[OwnerLabel] != "" || resource.GetAnnotations()["masque.galactic.datumapis.com/endpoint-uid"] != "" {
		return fmt.Errorf("legacy identity-bearing delivery requires explicit migration")
	}
	if receipt := deliveryReceipt(endpoint, resource); receipt != nil {
		if receipt.State == "Removed" {
			return fmt.Errorf("removed delivery unexpectedly exists")
		}
		if receipt.UID == "" {
			digest, err := deliveryDigest(resource)
			if err != nil || digest != receipt.ContentDigest {
				return fmt.Errorf("pending delivery content changed")
			}
			receipt.UID = string(resource.GetUID())
			receipt.State = "Created"
			return d.Project.Status().Update(ctx, endpoint)
		}
		if receipt.UID != string(resource.GetUID()) {
			return fmt.Errorf("delivery incarnation changed")
		}
		return nil
	}
	gvk := deliveryGVK(resource)
	return fmt.Errorf("delivery has no durable creation intent: %s %s/%s", gvk.Kind, resource.GetNamespace(), resource.GetName())
}

func (d *KubernetesDriver) migrateInventory(ctx context.Context, endpoint *connect.ConnectEndpoint) error {
	changed := false
	for index := range endpoint.Status.DeliveryReceipts {
		receipt := &endpoint.Status.DeliveryReceipts[index]
		knownKind := (receipt.APIVersion == "v1" && receipt.Kind == "Secret") || (receipt.APIVersion == registrationGVK.GroupVersion().String() && receipt.Kind == registrationGVK.Kind) || (receipt.APIVersion == policyGVK.GroupVersion().String() && receipt.Kind == policyGVK.Kind)
		if receipt.Namespace != d.RuntimeNamespace || !knownKind {
			return fmt.Errorf("delivery inventory does not match configured runtime scope")
		}
		if receipt.State == "" {
			receipt.State = "Planned"
			if receipt.UID != "" {
				receipt.State = "Created"
			}
			changed = true
		}
	}
	for _, name := range endpoint.Status.DeliveredSecrets {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: d.RuntimeNamespace, Name: name}}
		if deliveryReceipt(endpoint, secret) == nil {
			endpoint.Status.DeliveryReceipts = append(endpoint.Status.DeliveryReceipts, connect.EndpointDeliveryReceipt{State: "Planned", APIVersion: "v1", Kind: "Secret", Namespace: d.RuntimeNamespace, Name: name})
		}
		changed = true
	}
	if !changed {
		return nil
	}
	endpoint.Status.DeliveredSecrets = nil
	return d.Project.Status().Update(ctx, endpoint)
}

func secretNames(endpoint *connect.ConnectEndpoint) []string {
	return inventorySecretNames(endpoint, false)
}

func inventorySecretNames(endpoint *connect.ConnectEndpoint, includeRemoved bool) []string {
	var names []string
	seen := map[string]bool{}
	for index := len(endpoint.Status.DeliveryReceipts) - 1; index >= 0; index-- {
		receipt := endpoint.Status.DeliveryReceipts[index]
		if receipt.APIVersion != "v1" || receipt.Kind != "Secret" || seen[receipt.Name] {
			continue
		}
		seen[receipt.Name] = true
		if includeRemoved || receipt.State != "Removed" {
			names = append(names, receipt.Name)
		}
	}
	return names
}

func (d *KubernetesDriver) markRemoved(ctx context.Context, endpoint *connect.ConnectEndpoint, resource client.Object) error {
	receipt := deliveryReceipt(endpoint, resource)
	if receipt == nil || receipt.State == "Removed" {
		return nil
	}
	receipt.State = "Removed"
	return d.Project.Status().Update(ctx, endpoint)
}

func (d *KubernetesDriver) ensureDelivery(ctx context.Context, endpoint *connect.ConnectEndpoint, desired *unstructured.Unstructured) error {
	current := object(desired.GroupVersionKind(), desired.GetNamespace(), desired.GetName())
	if err := d.Karmada.Get(ctx, client.ObjectKeyFromObject(current), current); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		if err := d.prepareDelivery(ctx, endpoint, desired); err != nil {
			return err
		}
		if err := d.Karmada.Create(ctx, desired); err != nil {
			return err
		}
		return d.rememberDelivery(ctx, endpoint, desired)
	}
	if deliveryReceipt(endpoint, current) == nil && !reflect.DeepEqual(current.Object["spec"], desired.Object["spec"]) {
		return fmt.Errorf("unrecorded delivery differs from exact desired resource")
	}
	if err := d.rememberDelivery(ctx, endpoint, current); err != nil {
		return err
	}
	if reflect.DeepEqual(current.Object["spec"], desired.Object["spec"]) {
		return nil
	}
	if desired.GroupVersionKind() == registrationGVK {
		oldRevision, _, _ := unstructured.NestedInt64(current.Object, "spec", "revision")
		newRevision, _, _ := unstructured.NestedInt64(desired.Object, "spec", "revision")
		if oldRevision >= newRevision {
			return fmt.Errorf("stale registration update")
		}
		for _, field := range []string{"hostname", "provider"} {
			oldValue, _, _ := unstructured.NestedString(current.Object, "spec", field)
			newValue, _, _ := unstructured.NestedString(desired.Object, "spec", field)
			if oldValue != newValue {
				return fmt.Errorf("registration identity changed")
			}
		}
	}
	current.Object["spec"] = desired.Object["spec"]
	return d.Karmada.Update(ctx, current)
}

func (d *KubernetesDriver) ensureDeliverySecret(ctx context.Context, endpoint *connect.ConnectEndpoint, desired *corev1.Secret) error {
	current := &corev1.Secret{TypeMeta: desired.TypeMeta}
	if err := d.Karmada.Get(ctx, client.ObjectKeyFromObject(desired), current); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		if err := d.prepareDelivery(ctx, endpoint, desired); err != nil {
			return err
		}
		if err := d.Karmada.Create(ctx, desired); err != nil {
			return err
		}
		return d.rememberDelivery(ctx, endpoint, desired)
	}
	if current.Type != desired.Type || !reflect.DeepEqual(current.Data, desired.Data) || current.Annotations["masque.galactic.datumapis.com/certificate-revision"] != endpoint.Status.CertificateRevision {
		return fmt.Errorf("immutable certificate delivery differs")
	}
	return d.rememberDelivery(ctx, endpoint, current)
}

func (d *KubernetesDriver) removeDeliveryResource(ctx context.Context, endpoint *connect.ConnectEndpoint, resource client.Object) (bool, error) {
	if err := d.Karmada.Get(ctx, client.ObjectKeyFromObject(resource), resource); err != nil {
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	}
	receipt := deliveryReceipt(endpoint, resource)
	if receipt != nil && receipt.UID == "" {
		if err := d.rememberDelivery(ctx, endpoint, resource); err != nil {
			return false, err
		}
	}
	if receipt == nil || receipt.UID == "" || receipt.UID != string(resource.GetUID()) {
		return false, fmt.Errorf("refusing to delete unrecorded or replaced delivery")
	}
	uid, version := resource.GetUID(), resource.GetResourceVersion()
	err := d.Karmada.Delete(ctx, resource, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version}})
	return false, client.IgnoreNotFound(err)
}
