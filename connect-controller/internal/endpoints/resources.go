package endpoints

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var certificateGVK = schema.GroupVersionKind{Group: "certificates.miloapis.com", Version: "v1alpha1", Kind: "TLSCertificate"}
var recordGVK = schema.GroupVersionKind{Group: "dns.networking.miloapis.com", Version: "v1alpha1", Kind: "DNSRecordSet"}
var registrationGVK = schema.GroupVersionKind{Group: "galactic.datumapis.com", Version: "v1alpha1", Kind: "MASQUEEndpoint"}
var policyGVK = schema.GroupVersionKind{Group: "policy.karmada.io", Version: "v1alpha1", Kind: "PropagationPolicy"}

type KubernetesDriver struct {
	Project              client.Client
	Certificates         client.Client
	Karmada              client.Client
	Cells                map[string]client.Client
	CertificateNamespace string
	RuntimeNamespace     string
	Zone                 string
	Domain               string
	Now                  func() time.Time
	ProbeEndpoint        func(context.Context, *connect.ConnectEndpoint) error
}

func object(gvk schema.GroupVersionKind, namespace, name string) *unstructured.Unstructured {
	result := &unstructured.Unstructured{}
	result.SetGroupVersionKind(gvk)
	result.SetNamespace(namespace)
	result.SetName(name)
	return result
}

func owned(endpoint *connect.ConnectEndpoint, resource client.Object) bool {
	return endpoint.UID != "" && resource.GetLabels()[OwnerLabel] == string(endpoint.UID)
}

func ensure(ctx context.Context, target client.Client, endpoint *connect.ConnectEndpoint, desired *unstructured.Unstructured) error {
	desired.SetLabels(map[string]string{OwnerLabel: string(endpoint.UID)})
	current := object(desired.GroupVersionKind(), desired.GetNamespace(), desired.GetName())
	if err := target.Get(ctx, client.ObjectKeyFromObject(current), current); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		return target.Create(ctx, desired)
	}
	if !owned(endpoint, current) {
		return fmt.Errorf("resource ownership mismatch: %s", current.GetKind())
	}
	if desired.GroupVersionKind() == certificateGVK {
		for field, value := range desired.Object["spec"].(map[string]interface{}) {
			actual, _, err := unstructured.NestedFieldNoCopy(current.Object, "spec", field)
			if err != nil || !reflect.DeepEqual(actual, value) {
				return fmt.Errorf("certificate request identity changed")
			}
		}
		return nil
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
	}
	current.Object["spec"] = desired.Object["spec"]
	return target.Update(ctx, current)
}

func remove(ctx context.Context, target client.Client, endpoint *connect.ConnectEndpoint, resource client.Object) (bool, error) {
	if err := target.Get(ctx, client.ObjectKeyFromObject(resource), resource); err != nil {
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	}
	if !owned(endpoint, resource) {
		return false, fmt.Errorf("refusing to delete foreign resource")
	}
	uid := resource.GetUID()
	version := resource.GetResourceVersion()
	if err := target.Delete(ctx, resource, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version}}); client.IgnoreNotFound(err) != nil {
		return false, err
	}
	return false, nil
}

func (d *KubernetesDriver) Certificate(ctx context.Context, endpoint *connect.ConnectEndpoint) (Certificate, error) {
	request := object(certificateGVK, endpoint.Namespace, endpoint.Status.CertificateRef.Name)
	request.Object["spec"] = map[string]interface{}{"dnsNames": []interface{}{endpoint.Spec.Hostname}, "issuance": "DNS01", "managedAuthorization": map[string]interface{}{"reservationName": endpoint.Name, "reservationUID": string(endpoint.UID)}}
	if err := ensure(ctx, d.Project, endpoint, request); err != nil {
		return Certificate{}, err
	}
	if err := d.Project.Get(ctx, client.ObjectKeyFromObject(request), request); err != nil {
		return Certificate{}, err
	}
	if endpoint.Status.CertificateRef.UID == "" {
		endpoint.Status.CertificateRef.UID = string(request.GetUID())
		if err := d.Project.Status().Update(ctx, endpoint); err != nil {
			return Certificate{}, err
		}
		return Certificate{}, fmt.Errorf("certificate reservation bound; waiting for issuance")
	}
	if endpoint.Status.CertificateRef.UID != string(request.GetUID()) {
		return Certificate{}, fmt.Errorf("certificate UID changed")
	}
	records, _, err := unstructured.NestedSlice(request.Object, "status", "requiredDNSRecords")
	if err != nil {
		return Certificate{}, err
	}
	if len(records) != 1 {
		return Certificate{}, fmt.Errorf("waiting for exact challenge CNAME")
	}
	record, ok := records[0].(map[string]interface{})
	if !ok || record["type"] != "CNAME" || strings.TrimSuffix(fmt.Sprint(record["name"]), ".") != "_acme-challenge."+endpoint.Spec.Hostname {
		return Certificate{}, fmt.Errorf("invalid challenge record")
	}
	content, ok := record["content"].(string)
	if !ok || content == "" {
		return Certificate{}, fmt.Errorf("missing challenge target")
	}
	if err := d.record(ctx, endpoint, "challenge", fmt.Sprint(record["name"]), content); err != nil {
		return Certificate{}, err
	}
	conditions, _, _ := unstructured.NestedSlice(request.Object, "status", "conditions")
	ready := false
	for _, item := range conditions {
		condition, ok := item.(map[string]interface{})
		if ok && condition["type"] == "Ready" && condition["status"] == "True" && condition["observedGeneration"] == request.GetGeneration() {
			ready = true
		}
	}
	if !ready || !request.GetDeletionTimestamp().IsZero() {
		return Certificate{}, fmt.Errorf("certificate readiness pending")
	}
	revision, _, _ := unstructured.NestedString(request.Object, "status", "certificateRevision")
	if revision == "" {
		return Certificate{}, fmt.Errorf("certificate revision pending")
	}
	secret, leaf, err := d.storedCertificate(ctx, endpoint, revision)
	_ = secret
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{Revision: revision, NotAfter: leaf.NotAfter}, nil
}

func (d *KubernetesDriver) storedCertificate(ctx context.Context, endpoint *connect.ConnectEndpoint, revision string) (*corev1.Secret, *x509.Certificate, error) {
	sum := sha256.Sum256([]byte(endpoint.Status.CertificateRef.UID))
	secret := &corev1.Secret{}
	if err := d.Certificates.Get(ctx, client.ObjectKey{Namespace: d.CertificateNamespace, Name: "tc-" + hex.EncodeToString(sum[:16])}, secret); err != nil {
		return nil, nil, err
	}
	if secret.Labels["certificates.miloapis.com/upstream-uid"] != endpoint.Status.CertificateRef.UID || endpoint.Status.CertificateRef.UID == "" {
		return nil, nil, fmt.Errorf("stored certificate ownership mismatch")
	}
	leaf, err := ValidateCertificate(secret, endpoint.Spec.Hostname, revision, d.Now())
	return secret, leaf, err
}

func ValidateCertificate(secret *corev1.Secret, hostname, revision string, now time.Time) (*x509.Certificate, error) {
	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("stored certificate is not a TLS Secret")
	}
	pair, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil || len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("invalid stored key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("invalid leaf certificate")
	}
	sum := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(sum[:]) != revision {
		return nil, fmt.Errorf("certificate revision mismatch")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != hostname || leaf.VerifyHostname(hostname) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate name or validity mismatch")
	}
	return leaf, nil
}

func (d *KubernetesDriver) record(ctx context.Context, endpoint *connect.ConnectEndpoint, suffix, name, content string) error {
	name = strings.TrimSuffix(name, ".")
	domain := strings.TrimSuffix(d.Domain, ".")
	zone := object(schema.GroupVersionKind{Group: recordGVK.Group, Version: recordGVK.Version, Kind: "DNSZone"}, endpoint.Namespace, d.Zone)
	if err := d.Project.Get(ctx, client.ObjectKeyFromObject(zone), zone); err != nil {
		return err
	}
	zoneDomain, _, _ := unstructured.NestedString(zone.Object, "spec", "domainName")
	if strings.TrimSuffix(zoneDomain, ".") != domain {
		return fmt.Errorf("shared DNSZone domain mismatch")
	}
	if !strings.HasSuffix(name, "."+domain) {
		return fmt.Errorf("DNS name outside managed zone")
	}
	resource := object(recordGVK, endpoint.Namespace, endpoint.Name+"-"+suffix)
	resource.Object["spec"] = map[string]interface{}{"dnsZoneRef": map[string]interface{}{"name": d.Zone}, "recordType": "CNAME", "records": []interface{}{map[string]interface{}{"name": strings.TrimSuffix(name, "."+domain), "ttl": int64(60), "cname": map[string]interface{}{"content": content}}}}
	return ensure(ctx, d.Project, endpoint, resource)
}

func (d *KubernetesDriver) Route(ctx context.Context, endpoint *connect.ConnectEndpoint, enabled bool) error {
	if enabled {
		return d.record(ctx, endpoint, "route", endpoint.Spec.Hostname, endpoint.Spec.Assignment.Frontend)
	}
	done, err := remove(ctx, d.Project, endpoint, object(recordGVK, endpoint.Namespace, endpoint.Name+"-route"))
	if err == nil && !done {
		return fmt.Errorf("routing record deletion pending")
	}
	return err
}

func (d *KubernetesDriver) Apply(ctx context.Context, endpoint *connect.ConnectEndpoint, enabled bool) error {
	latest := &connect.ConnectEndpoint{}
	if err := d.Project.Get(ctx, client.ObjectKeyFromObject(endpoint), latest); err != nil {
		return err
	}
	if latest.UID != endpoint.UID || latest.Status.Revision != endpoint.Status.Revision || (enabled && latest.Spec.Lifecycle != "Active") {
		return fmt.Errorf("stale endpoint worker")
	}
	secretName := SecretName(endpoint)
	if enabled {
		stored, _, err := d.storedCertificate(ctx, endpoint, endpoint.Status.CertificateRevision)
		if err != nil {
			return err
		}
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: d.RuntimeNamespace, Labels: map[string]string{OwnerLabel: string(endpoint.UID)}, Annotations: map[string]string{"masque.galactic.datumapis.com/endpoint-uid": string(endpoint.UID), "masque.galactic.datumapis.com/certificate-revision": endpoint.Status.CertificateRevision}}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: stored.Data[corev1.TLSCertKey], corev1.TLSPrivateKeyKey: stored.Data[corev1.TLSPrivateKeyKey]}}
		current := &corev1.Secret{}
		if err := d.Karmada.Get(ctx, client.ObjectKeyFromObject(secret), current); err != nil {
			if !apierrors.IsNotFound(err) {
				return err
			}
			if err := d.Karmada.Create(ctx, secret); err != nil {
				return err
			}
		} else {
			if !owned(endpoint, current) {
				return fmt.Errorf("delivered Secret ownership mismatch")
			}
			if !reflect.DeepEqual(current.Data, secret.Data) {
				return fmt.Errorf("immutable certificate delivery differs")
			}
		}
	}
	registration := object(registrationGVK, d.RuntimeNamespace, endpoint.Name)
	assignment := endpoint.Spec.Assignment
	certificateRevision := endpoint.Status.CertificateRevision
	if !enabled && certificateRevision == "" {
		certificateRevision = strings.Repeat("0", 64)
	}
	registration.Object["spec"] = map[string]interface{}{"endpointUID": string(endpoint.UID), "customerProjectUID": endpoint.Spec.CustomerProjectUID, "gatewayUID": endpoint.Spec.GatewayUID, "networkUID": endpoint.Spec.NetworkUID, "metro": endpoint.Spec.Metro, "cell": assignment.Cell, "provider": assignment.Provider, "hostname": endpoint.Spec.Hostname, "vpcRef": map[string]interface{}{"namespace": assignment.VPC.Namespace, "name": assignment.VPC.Name, "uid": assignment.VPC.UID}, "revision": endpoint.Status.Revision, "certificateRef": map[string]interface{}{"name": secretName, "revision": certificateRevision}, "enabled": enabled}
	if err := ensure(ctx, d.Karmada, endpoint, registration); err != nil {
		return err
	}
	policy := object(policyGVK, d.RuntimeNamespace, endpoint.Name)
	selectors := []interface{}{map[string]interface{}{"apiVersion": registrationGVK.GroupVersion().String(), "kind": registrationGVK.Kind, "name": endpoint.Name}}
	for _, name := range endpoint.Status.DeliveredSecrets {
		selectors = append(selectors, map[string]interface{}{"apiVersion": "v1", "kind": "Secret", "name": name})
	}
	policy.Object["spec"] = map[string]interface{}{"resourceSelectors": selectors, "propagateDeps": false, "placement": map[string]interface{}{"clusterAffinity": map[string]interface{}{"clusterNames": []interface{}{assignment.Cell}}}}
	return ensure(ctx, d.Karmada, endpoint, policy)
}

func SecretName(endpoint *connect.ConnectEndpoint) string {
	if endpoint.Status.CertificateRevision == "" {
		return endpoint.Name + "-tls"
	}
	return endpoint.Name + "-" + endpoint.Status.CertificateRevision
}

func (d *KubernetesDriver) Prune(ctx context.Context, endpoint *connect.ConnectEndpoint) error {
	for _, name := range endpoint.Status.DeliveredSecrets {
		if name == SecretName(endpoint) {
			continue
		}
		done, err := d.removeSecret(ctx, endpoint, name)
		if err != nil {
			return err
		}
		if !done {
			return fmt.Errorf("previous delivered certificate removal pending")
		}
	}
	return nil
}

func (d *KubernetesDriver) removeSecret(ctx context.Context, endpoint *connect.ConnectEndpoint, name string) (bool, error) {
	cell := d.Cells[endpoint.Spec.Assignment.Cell]
	if cell == nil {
		return false, fmt.Errorf("selected cell unavailable")
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: d.RuntimeNamespace, Name: name}}
	done, err := remove(ctx, d.Karmada, endpoint, secret)
	if err != nil || !done {
		return false, err
	}
	err = cell.Get(ctx, client.ObjectKeyFromObject(secret), secret)
	return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
}

func (d *KubernetesDriver) Probe(ctx context.Context, endpoint *connect.ConnectEndpoint) error {
	if d.ProbeEndpoint == nil {
		return fmt.Errorf("external probe is not configured")
	}
	return d.ProbeEndpoint(ctx, endpoint)
}

func (d *KubernetesDriver) RemoveDelivery(ctx context.Context, endpoint *connect.ConnectEndpoint) (bool, error) {
	cell := d.Cells[endpoint.Spec.Assignment.Cell]
	if cell == nil {
		return false, fmt.Errorf("selected cell unavailable")
	}
	for _, resource := range []client.Object{object(registrationGVK, d.RuntimeNamespace, endpoint.Name)} {
		done, err := remove(ctx, d.Karmada, endpoint, resource)
		if err != nil || !done {
			return false, err
		}
		if err := cell.Get(ctx, client.ObjectKeyFromObject(resource), resource); !apierrors.IsNotFound(err) {
			if err != nil {
				return false, err
			}
			return false, nil
		}
	}
	for _, name := range endpoint.Status.DeliveredSecrets {
		done, err := d.removeSecret(ctx, endpoint, name)
		if err != nil || !done {
			return false, err
		}
	}
	return remove(ctx, d.Karmada, endpoint, object(policyGVK, d.RuntimeNamespace, endpoint.Name))
}

func (d *KubernetesDriver) RemoveCertificate(ctx context.Context, endpoint *connect.ConnectEndpoint) (bool, error) {
	if endpoint.Status.CertificateRef.Name != "" {
		done, err := remove(ctx, d.Project, endpoint, object(certificateGVK, endpoint.Namespace, endpoint.Status.CertificateRef.Name))
		if err != nil || !done {
			return false, err
		}
	}
	if endpoint.Status.CertificateRef.UID != "" {
		sum := sha256.Sum256([]byte(endpoint.Status.CertificateRef.UID))
		secret := &corev1.Secret{}
		err := d.Certificates.Get(ctx, client.ObjectKey{Namespace: d.CertificateNamespace, Name: "tc-" + hex.EncodeToString(sum[:16])}, secret)
		if !apierrors.IsNotFound(err) {
			return false, err
		}
	}
	return remove(ctx, d.Project, endpoint, object(recordGVK, endpoint.Namespace, endpoint.Name+"-challenge"))
}
