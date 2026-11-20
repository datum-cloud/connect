package credentials

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	"github.com/google/uuid"
	connect "go.datum.net/connect-controller/api/v1alpha1"
	"go.datum.net/connect-controller/internal/endpoints"
	cloud "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/pkg/masquegrant"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type GrantAPI interface {
	Create(context.Context, masquegrant.CreateRequest) (masquegrant.Issued, error)
	Rotate(context.Context, string, time.Duration) (masquegrant.Issued, error)
	Retire(context.Context, string) error
}

type ManagedIssuer struct {
	Project          client.Client
	Namespace        string
	Authorities      map[string]GrantAPI
	Cells            map[string]client.Reader
	RuntimeNamespace string
	Now              func() time.Time
}

func (issuer *ManagedIssuer) Mint(ctx context.Context, binding Binding) (IssuedTransport, error) {
	if binding.Endpoint == nil || binding.UID == "" || binding.PolicyRevision == "" || binding.NetworkUID == "" || binding.NetworkName == "" || binding.VPC.UID == "" || issuer.RuntimeNamespace == "" {
		return IssuedTransport{}, ErrUnavailable
	}
	endpoint := &connect.ConnectEndpoint{}
	if err := issuer.Project.Get(ctx, client.ObjectKeyFromObject(binding.Endpoint), endpoint); err != nil {
		return IssuedTransport{}, err
	}
	if endpoint.UID != binding.Endpoint.UID || !endpoints.Ready(endpoint, issuer.Now(), 5*time.Minute) {
		return IssuedTransport{}, ErrUnavailable
	}
	authority := issuer.Authorities[endpoint.Spec.Assignment.Cell]
	if authority == nil {
		return IssuedTransport{}, ErrUnavailable
	}
	if err := issuer.validateVPC(ctx, endpoint.Spec.Assignment.Cell, binding.VPC); err != nil {
		return IssuedTransport{}, err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", binding.UID, endpoint.UID, binding.PolicyRevision+"/"+binding.NetworkUID+"/"+binding.VPC.UID, endpoint.Status.ActivationRevision)))
	connector := uuid.NewSHA1(uuid.NameSpaceOID, digest[:]).String()
	receipt := &connect.ConnectGrant{ObjectMeta: metav1.ObjectMeta{Namespace: issuer.Namespace, Name: "cg-" + connector}, Spec: connect.ConnectGrantSpec{NetworkName: binding.NetworkName, NetworkUID: binding.NetworkUID, VPC: binding.VPC, EndpointName: endpoint.Name, EndpointUID: string(endpoint.UID), BindingName: binding.Name, BindingUID: binding.UID, PolicyRevision: binding.PolicyRevision, ConnectorID: connector, Cell: endpoint.Spec.Assignment.Cell}}
	wanted := receipt.Spec
	if err := issuer.Project.Create(ctx, receipt); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return IssuedTransport{}, err
		}
		if err := issuer.Project.Get(ctx, client.ObjectKeyFromObject(receipt), receipt); err != nil {
			return IssuedTransport{}, err
		}
		if !reflect.DeepEqual(receipt.Spec, wanted) || receipt.Status.EffectiveState() != "Active" {
			return IssuedTransport{}, ErrUnavailable
		}
	}
	if receipt.Status.State != "Active" {
		receipt.Status = connect.ConnectGrantStatus{State: "Active"}
		if err := issuer.Project.Status().Update(ctx, receipt); err != nil {
			return IssuedTransport{}, err
		}
	}
	routes := make([]netip.Prefix, 0, len(binding.NetworkPlan.DestinationPrefixes))
	receiptUID := receipt.UID
	for _, raw := range binding.NetworkPlan.DestinationPrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is6() || prefix != prefix.Masked() {
			return IssuedTransport{}, ErrUnavailable
		}
		routes = append(routes, prefix)
	}
	assignment := endpoint.Spec.Assignment
	activation := endpoint.Status.ActivationRevision
	reference := &masquegrant.EndpointRef{Namespace: issuer.RuntimeNamespace, Name: endpoint.Name}
	issued, err := authority.Create(ctx, masquegrant.CreateRequest{VPC: masquegrant.VPCRef{Namespace: binding.VPC.Namespace, Name: binding.VPC.Name}, Connector: connector, Lifetime: 5 * time.Minute, Routes: routes, EndpointRef: reference})
	if apierrors.IsAlreadyExists(err) {
		issued, err = authority.Rotate(ctx, connector, 5*time.Minute)
	}
	if err != nil {
		return IssuedTransport{}, fmt.Errorf("authority mint failed")
	}
	if err := issuer.validateVPC(ctx, assignment.Cell, binding.VPC); err != nil {
		_ = issuer.Retire(ctx, receipt)
		return IssuedTransport{}, ErrUnavailable
	}
	if err := issuer.Project.Get(ctx, client.ObjectKeyFromObject(receipt), receipt); err != nil || receipt.UID != receiptUID || !reflect.DeepEqual(receipt.Spec, wanted) || receipt.Status.EffectiveState() != "Active" {
		_ = authority.Retire(ctx, connector)
		return IssuedTransport{}, ErrUnavailable
	}
	if err := issuer.Project.Get(ctx, client.ObjectKeyFromObject(endpoint), endpoint); err != nil || endpoint.UID != binding.Endpoint.UID || endpoint.Status.ActivationRevision != activation || !endpoints.Ready(endpoint, issuer.Now(), 5*time.Minute) {
		_ = authority.Retire(ctx, connector)
		return IssuedTransport{}, ErrUnavailable
	}
	if !issued.Prefix.IsValid() || !issued.Prefix.Addr().Is6() || issued.Prefix.Bits() != 96 || issued.Connector != connector || issued.VPC != binding.VPC.Namespace+"/"+binding.VPC.Name {
		_ = issuer.Retire(ctx, receipt)
		return IssuedTransport{}, ErrUnavailable
	}
	return IssuedTransport{Authority: endpoint.Spec.Hostname, VPCSelector: issued.VPC, Credential: Credential(issued.Credential), ExpiresAt: issued.Expires, Transports: []string{"h3", "h2"}, ExpectedPrefix: issued.Prefix.String()}, nil
}

func (issuer *ManagedIssuer) validateVPC(ctx context.Context, cellName string, expected connect.EndpointVPCReference) error {
	reader := issuer.Cells[cellName]
	if reader == nil {
		return ErrUnavailable
	}
	vpc := &cloud.VPC{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: expected.Namespace, Name: expected.Name}, vpc); err != nil || vpc.UID == "" || string(vpc.UID) != expected.UID || vpc.DeletionTimestamp != nil {
		return ErrUnavailable
	}
	return nil
}

func (issuer *ManagedIssuer) Retire(ctx context.Context, receipt *connect.ConnectGrant) error {
	if receipt.Status.EffectiveState() != "Retired" {
		receipt.Status = connect.ConnectGrantStatus{State: "Retiring"}
		if err := issuer.Project.Status().Update(ctx, receipt); err != nil {
			return err
		}
	}
	authority := issuer.Authorities[receipt.Spec.Cell]
	if authority == nil {
		return ErrUnavailable
	}
	if err := authority.Retire(ctx, receipt.Spec.ConnectorID); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if receipt.Status.State == "Retired" && !receipt.Status.Retired && !receipt.Status.Retiring {
		return nil
	}
	receipt.Status = connect.ConnectGrantStatus{State: "Retired"}
	return issuer.Project.Status().Update(ctx, receipt)
}
