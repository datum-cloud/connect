package endpoints

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type InstanceAck struct {
	InstanceName               string      `json:"instanceName"`
	ObservedRevision           int64       `json:"observedRevision"`
	AppliedRevision            int64       `json:"appliedRevision"`
	AppliedCertificateRevision string      `json:"appliedCertificateRevision"`
	State                      string      `json:"state"`
	ForwardingStopped          bool        `json:"forwardingStopped"`
	LastHeartbeatTime          metav1.Time `json:"lastHeartbeatTime"`
}

func (d *KubernetesDriver) Applied(ctx context.Context, endpoint *connect.ConnectEndpoint, enabled bool) error {
	cell := d.Cells[endpoint.Spec.Assignment.Cell]
	if cell == nil {
		return fmt.Errorf("selected cell unavailable")
	}
	registration := object(registrationGVK, d.RuntimeNamespace, endpoint.Name)
	if err := cell.Get(ctx, client.ObjectKeyFromObject(registration), registration); err != nil {
		return err
	}
	revision, _, _ := unstructured.NestedInt64(registration.Object, "spec", "revision")
	if revision != endpoint.Status.Revision || registration.GetDeletionTimestamp() != nil {
		return fmt.Errorf("registration identity or revision not delivered")
	}
	for field, wanted := range map[string]string{"hostname": endpoint.Spec.Hostname, "provider": endpoint.Spec.Assignment.Provider} {
		actual, _, _ := unstructured.NestedString(registration.Object, "spec", field)
		if actual != wanted {
			return fmt.Errorf("registration scope differs")
		}
	}
	actualEnabled, _, _ := unstructured.NestedBool(registration.Object, "spec", "enabled")
	if actualEnabled != enabled {
		return fmt.Errorf("registration enable state differs")
	}
	if enabled {
		name, _, _ := unstructured.NestedString(registration.Object, "spec", "certificateRef", "name")
		certificate, _, _ := unstructured.NestedString(registration.Object, "spec", "certificateRef", "revision")
		if certificate != endpoint.Status.CertificateRevision || name != SecretName(endpoint) {
			return fmt.Errorf("registration certificate differs")
		}
	}
	entries, _, _ := unstructured.NestedSlice(registration.Object, "status", "instances")
	encoded, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	var acknowledgments []InstanceAck
	if err := json.Unmarshal(encoded, &acknowledgments); err != nil {
		return err
	}
	acks := map[string]InstanceAck{}
	for _, ack := range acknowledgments {
		if _, exists := acks[ack.InstanceName]; exists {
			return fmt.Errorf("duplicate instance acknowledgment")
		}
		acks[ack.InstanceName] = ack
	}
	instances := &unstructured.UnstructuredList{}
	instances.SetGroupVersionKind(schema.GroupVersionKind{Group: registrationGVK.Group, Version: registrationGVK.Version, Kind: "EdgeInstanceList"})
	if err := cell.List(ctx, instances, client.InNamespace(d.RuntimeNamespace)); err != nil {
		return err
	}
	relevant := 0
	for _, instance := range instances.Items {
		provider, _, _ := unstructured.NestedString(instance.Object, "spec", "providerRef", "name")
		if provider != endpoint.Spec.Assignment.Provider {
			continue
		}
		relevant++
		podUID, _, _ := unstructured.NestedString(instance.Object, "spec", "podUID")
		created := instance.GetCreationTimestamp()
		if podUID == "" || instance.GetUID() == "" || instance.GetName() != "ei-"+podUID || created.IsZero() || instance.GetDeletionTimestamp() != nil {
			return fmt.Errorf("invalid provider incarnation")
		}
		lease := &coordinationv1.Lease{}
		if err := cell.Get(ctx, client.ObjectKeyFromObject(&instance), lease); err != nil {
			return err
		}
		ownerMatches := false
		for _, owner := range lease.OwnerReferences {
			if owner.UID == instance.GetUID() && owner.Kind == "EdgeInstance" {
				ownerMatches = true
			}
		}
		now := d.Now()
		if lease.Spec.AcquireTime == nil || lease.Spec.AcquireTime.IsZero() || lease.Spec.AcquireTime.After(now) || lease.DeletionTimestamp != nil {
			return fmt.Errorf("provider lease incarnation is not established")
		}
		if !ownerMatches || lease.UID == "" || lease.Annotations["galactic.datumapis.com/edge-pod-uid"] != podUID || lease.Annotations["galactic.datumapis.com/edge-released"] == "true" || lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" || lease.Spec.RenewTime.After(now) || !now.Before(lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds)*time.Second)) {
			return fmt.Errorf("provider membership is not fresh")
		}
		ack, exists := acks[instance.GetName()]
		if !exists || !ack.LastHeartbeatTime.After(created.Time) || !ack.LastHeartbeatTime.After(lease.Spec.AcquireTime.Time) || ack.LastHeartbeatTime.After(now) || now.Sub(ack.LastHeartbeatTime.Time) > 10*time.Second || ack.ObservedRevision != endpoint.Status.Revision || ack.AppliedRevision != endpoint.Status.Revision {
			return fmt.Errorf("provider has not acknowledged current registration")
		}
		if enabled {
			if ack.State != "Applied" || ack.AppliedCertificateRevision != endpoint.Status.CertificateRevision {
				return fmt.Errorf("provider certificate not applied")
			}
		} else if ack.State != "Disabled" || !ack.ForwardingStopped {
			return fmt.Errorf("provider forwarding has not stopped")
		}
	}
	if relevant == 0 {
		return fmt.Errorf("no relevant provider instances")
	}
	return nil
}

type ProbeReport struct {
	EndpointRef         ProbeEndpointReference `json:"endpointRef"`
	Hostname            string                 `json:"hostname"`
	Revision            int64                  `json:"revision"`
	CertificateRevision string                 `json:"certificateRevision"`
	Cell                string                 `json:"cell"`
	CheckedAt           time.Time              `json:"checkedAt"`
	HTTP3               bool                   `json:"h3"`
	HTTP2               bool                   `json:"h2"`
	DNS                 bool                   `json:"dns"`
}

type ProbeEndpointReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func HTTPProbe(baseURL, runtimeNamespace string, httpClient *http.Client, now func() time.Time) (func(context.Context, *connect.ConnectEndpoint) error, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || runtimeNamespace == "" || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("probe URL must be trusted HTTPS endpoint")
	}
	return func(ctx context.Context, endpoint *connect.ConnectEndpoint) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/"+url.PathEscape(runtimeNamespace)+"/"+url.PathEscape(endpoint.Name), nil)
		if err != nil {
			return err
		}
		response, err := httpClient.Do(request)
		if err != nil {
			return fmt.Errorf("external probe unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("external probe failed")
		}
		var report ProbeReport
		if err := json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&report); err != nil {
			return fmt.Errorf("invalid probe response")
		}
		if report.EndpointRef.Namespace != runtimeNamespace || report.EndpointRef.Name != endpoint.Name || report.Hostname != endpoint.Spec.Hostname || report.Revision != endpoint.Status.Revision || report.CertificateRevision != endpoint.Status.CertificateRevision || report.Cell != endpoint.Spec.Assignment.Cell || report.CheckedAt.After(now()) || now().Sub(report.CheckedAt) > 10*time.Second || !report.HTTP3 || !report.HTTP2 || !report.DNS {
			return fmt.Errorf("external verification incomplete or stale")
		}
		return nil
	}, nil
}
