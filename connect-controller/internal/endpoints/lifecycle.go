package endpoints

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const OwnerLabel = "connect.datumapis.com/endpoint-uid"

type Certificate struct {
	Revision string
	NotAfter time.Time
}

type Driver interface {
	Certificate(context.Context, *connect.ConnectEndpoint) (Certificate, error)
	Apply(context.Context, *connect.ConnectEndpoint, bool) error
	Applied(context.Context, *connect.ConnectEndpoint, bool) error
	Route(context.Context, *connect.ConnectEndpoint, bool) error
	Probe(context.Context, *connect.ConnectEndpoint) error
	Prune(context.Context, *connect.ConnectEndpoint) error
	RemoveDelivery(context.Context, *connect.ConnectEndpoint) (bool, error)
	RemoveCertificate(context.Context, *connect.ConnectEndpoint) (bool, error)
}

type Reconciler struct {
	Project      client.Client
	Driver       Driver
	Now          func() time.Time
	ExpiryMargin time.Duration
	DNSDrain     time.Duration
}

func Name(projectUID, gatewayUID, metro string) string {
	sum := sha256.Sum256([]byte(projectUID + "\x00" + gatewayUID + "\x00" + metro))
	return "ce-" + hex.EncodeToString(sum[:20])
}

func Reserve(ctx context.Context, project client.Client, namespace, domain string, spec connect.ConnectEndpointSpec) (*connect.ConnectEndpoint, error) {
	if spec.CustomerProjectUID == "" || spec.GatewayUID == "" || spec.Metro == "" || domain == "" {
		return nil, fmt.Errorf("reservation requires project UID, gateway UID, metro and domain")
	}
	name := Name(spec.CustomerProjectUID, spec.GatewayUID, spec.Metro)
	label := make([]byte, 20)
	if _, err := rand.Read(label); err != nil {
		return nil, err
	}
	spec.Hostname = "gw-" + hex.EncodeToString(label) + "." + strings.TrimSuffix(domain, ".")
	spec.Lifecycle = "Active"
	endpoint := &connect.ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Spec: spec}
	if err := project.Create(ctx, endpoint); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
		if err := project.Get(ctx, client.ObjectKeyFromObject(endpoint), endpoint); err != nil {
			return nil, err
		}
		if endpoint.Spec.CustomerProjectUID != spec.CustomerProjectUID || endpoint.Spec.GatewayUID != spec.GatewayUID || endpoint.Spec.Metro != spec.Metro || !strings.HasSuffix(endpoint.Spec.Hostname, "."+strings.TrimSuffix(domain, ".")) {
			return nil, fmt.Errorf("reservation identity collision")
		}
		if endpoint.Spec.Lifecycle != "Active" {
			return nil, fmt.Errorf("reservation is retired or draining")
		}
	}
	return endpoint, nil
}

func Metros(locations map[string]string) ([]string, error) {
	set := map[string]bool{}
	for location, metro := range locations {
		if metro == "" {
			return nil, fmt.Errorf("Location %s has no metro", location)
		}
		set[metro] = true
	}
	result := make([]string, 0, len(set))
	for metro := range set {
		result = append(result, metro)
	}
	sort.Strings(result)
	return result, nil
}

func (r *Reconciler) Reconcile(ctx context.Context, key types.NamespacedName) error {
	endpoint := &connect.ConnectEndpoint{}
	if err := r.Project.Get(ctx, key, endpoint); err != nil {
		return client.IgnoreNotFound(err)
	}
	if endpoint.Spec.Lifecycle == "Retired" {
		return nil
	}
	if endpoint.Spec.Lifecycle != "Active" || !endpoint.DeletionTimestamp.IsZero() {
		return r.cleanup(ctx, endpoint)
	}
	if endpoint.Status.Phase == "Retired" {
		endpoint.Status = connect.ConnectEndpointStatus{Revision: endpoint.Status.Revision}
	}
	if endpoint.Status.Phase == "" {
		endpoint.Status.Phase = "Active"
		endpoint.Status.ActivationRevision = endpoint.Status.Revision + 1
		endpoint.Status.CertificateRef.Name = endpoint.Name
		endpoint.Status.Reason = "CertificatePending"
		return r.Project.Status().Update(ctx, endpoint)
	}
	if endpoint.Status.NotAfter != nil && !endpoint.Status.NotAfter.After(r.Now().Add(r.ExpiryMargin)) {
		if err := r.Driver.Route(ctx, endpoint, false); err != nil {
			return r.blocked(ctx, endpoint, "DNSWithdrawalPending", err)
		}
	}
	certificate, err := r.Driver.Certificate(ctx, endpoint)
	if err != nil {
		return r.blocked(ctx, endpoint, "CertificatePending", err)
	}
	if !certificate.NotAfter.After(r.Now().Add(r.ExpiryMargin)) {
		if err := r.Driver.Route(ctx, endpoint, false); err != nil {
			return r.blocked(ctx, endpoint, "DNSWithdrawalPending", err)
		}
		return r.blocked(ctx, endpoint, "CertificateExpiring", fmt.Errorf("certificate inside expiry margin"))
	}
	if certificate.Revision != endpoint.Status.CertificateRevision {
		endpoint.Status.Ready = false
		endpoint.Status.VerifiedAt = nil
		endpoint.Status.Revision++
		endpoint.Status.CertificateRevision = certificate.Revision
		secretName := SecretName(endpoint)
		found := false
		for _, name := range endpoint.Status.DeliveredSecrets {
			if name == secretName {
				found = true
			}
		}
		if !found {
			endpoint.Status.DeliveredSecrets = append(endpoint.Status.DeliveredSecrets, secretName)
		}
		expires := metav1.NewTime(certificate.NotAfter)
		endpoint.Status.NotAfter = &expires
		endpoint.Status.Reason = "ListenerPending"
		return r.Project.Status().Update(ctx, endpoint)
	}
	if err := r.Driver.Apply(ctx, endpoint, true); err != nil {
		return r.blocked(ctx, endpoint, "DistributionPending", err)
	}
	if err := r.Driver.Applied(ctx, endpoint, true); err != nil {
		return r.blocked(ctx, endpoint, "ListenerPending", err)
	}
	if err := r.Driver.Route(ctx, endpoint, true); err != nil {
		return r.blocked(ctx, endpoint, "DNSPending", err)
	}
	if err := r.Driver.Probe(ctx, endpoint); err != nil {
		return r.blocked(ctx, endpoint, "ProbePending", err)
	}
	if err := r.Driver.Prune(ctx, endpoint); err != nil {
		return r.blocked(ctx, endpoint, "PreviousCertificateCleanupPending", err)
	}
	endpoint.Status.DeliveredSecrets = []string{SecretName(endpoint)}
	endpoint.Status.Ready = true
	endpoint.Status.Reason = "Ready"
	verified := metav1.NewTime(r.Now())
	endpoint.Status.VerifiedAt = &verified
	return r.Project.Status().Update(ctx, endpoint)
}

func (r *Reconciler) blocked(ctx context.Context, endpoint *connect.ConnectEndpoint, reason string, cause error) error {
	endpoint.Status.Ready = false
	endpoint.Status.VerifiedAt = nil
	endpoint.Status.Reason = reason
	if err := r.Project.Status().Update(ctx, endpoint); err != nil {
		return err
	}
	return fmt.Errorf("%s: %w", reason, cause)
}

func (r *Reconciler) cleanup(ctx context.Context, endpoint *connect.ConnectEndpoint) error {
	endpoint.Status.Ready = false
	endpoint.Status.VerifiedAt = nil
	endpoint.Status.Phase = "Deleting"
	if endpoint.Status.CleanupStep == "" {
		endpoint.Status.Revision++
		endpoint.Status.CleanupStep = "Disable"
		if endpoint.Spec.Assignment.Cell == "" {
			endpoint.Status.CleanupStep = "Certificate"
		}
		return r.Project.Status().Update(ctx, endpoint)
	}
	switch endpoint.Status.CleanupStep {
	case "Disable":
		if err := r.Driver.Apply(ctx, endpoint, false); err != nil {
			return err
		}
		if err := r.Driver.Applied(ctx, endpoint, false); err != nil {
			return err
		}
		endpoint.Status.CleanupStep = "Withdraw"
	case "Withdraw":
		if err := r.Driver.Route(ctx, endpoint, false); err != nil {
			return err
		}
		now := metav1.NewTime(r.Now())
		endpoint.Status.WithdrawnAt = &now
		endpoint.Status.CleanupStep = "Drain"
	case "Drain":
		if endpoint.Status.WithdrawnAt == nil || r.Now().Before(endpoint.Status.WithdrawnAt.Add(r.DNSDrain)) {
			return nil
		}
		endpoint.Status.CleanupStep = "Delivery"
	case "Delivery":
		done, err := r.Driver.RemoveDelivery(ctx, endpoint)
		if err != nil || !done {
			return err
		}
		endpoint.Status.CleanupStep = "Certificate"
	case "Certificate":
		done, err := r.Driver.RemoveCertificate(ctx, endpoint)
		if err != nil || !done {
			return err
		}
		endpoint.Status.CleanupStep = "Retired"
	case "Retired":
		var grants connect.ConnectGrantList
		if err := r.Project.List(ctx, &grants, client.InNamespace(endpoint.Namespace)); err != nil {
			return err
		}
		for _, grant := range grants.Items {
			if grant.Spec.EndpointUID == string(endpoint.UID) && !grant.Status.Retired {
				return nil
			}
		}
		endpoint.Status.Phase = "Retired"
		if err := r.Project.Status().Update(ctx, endpoint); err != nil {
			return err
		}
		endpoint.Spec.Lifecycle = "Retired"
		return r.Project.Update(ctx, endpoint)
	default:
		return fmt.Errorf("unknown cleanup step")
	}
	endpoint.Status.Reason = "CleanupPending"
	return r.Project.Status().Update(ctx, endpoint)
}

func Ready(endpoint *connect.ConnectEndpoint, now time.Time, margin time.Duration) bool {
	return endpoint.Spec.Lifecycle == "Active" && endpoint.DeletionTimestamp.IsZero() && endpoint.Status.Phase == "Active" && endpoint.Status.Ready && endpoint.Status.Revision > 0 && endpoint.Status.CertificateRevision != "" && endpoint.Status.NotAfter != nil && endpoint.Status.NotAfter.After(now.Add(margin)) && endpoint.Status.VerifiedAt != nil && !endpoint.Status.VerifiedAt.After(now) && now.Sub(endpoint.Status.VerifiedAt.Time) <= 10*time.Second
}
