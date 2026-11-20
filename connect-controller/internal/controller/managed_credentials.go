package controller

import (
	"context"
	"fmt"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	"go.datum.net/connect-controller/internal/credentials"
	"go.datum.net/connect-controller/internal/endpoints"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GrantStillAuthorized(ctx context.Context, customer client.Client, endpoint *connect.ConnectEndpoint, receipt *connect.ConnectGrant) (bool, error) {
	binding := &connect.ConnectNetworkBinding{}
	if err := customer.Get(ctx, client.ObjectKey{Namespace: endpoint.Spec.GatewayNamespace, Name: receipt.Spec.BindingName}, binding); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if string(binding.UID) != receipt.Spec.BindingUID || !binding.DeletionTimestamp.IsZero() {
		return false, nil
	}
	gateway := &connect.ConnectGateway{}
	if err := customer.Get(ctx, client.ObjectKey{Namespace: binding.Namespace, Name: binding.Spec.GatewayRef}, gateway); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if string(gateway.UID) != endpoint.Spec.GatewayUID || !gateway.DeletionTimestamp.IsZero() {
		return false, nil
	}
	connector := &connect.Connector{}
	if err := customer.Get(ctx, client.ObjectKey{Namespace: binding.Namespace, Name: binding.Spec.ConnectorRef}, connector); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if !connector.DeletionTimestamp.IsZero() {
		return false, nil
	}
	network := &unstructured.Unstructured{}
	network.SetGroupVersionKind(schema.GroupVersionKind{Group: "networking.datumapis.com", Version: "v1alpha", Kind: "Network"})
	if err := customer.Get(ctx, client.ObjectKey{Namespace: binding.Namespace, Name: binding.Spec.NetworkRef}, network); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if string(network.GetUID()) != receipt.Spec.NetworkUID || binding.Spec.NetworkRef != receipt.Spec.NetworkName || !network.GetDeletionTimestamp().IsZero() {
		return false, nil
	}
	prefix, err := networkPrefix(ctx, customer, binding.Namespace, binding.Spec.NetworkRef)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var policies connect.ConnectConnectionPolicyList
	if err := customer.List(ctx, &policies, client.InNamespace(binding.Namespace)); err != nil {
		return false, err
	}
	revision, count, err := effectivePolicyRevision(policies.Items, connector, gateway, prefix, binding.Spec.NetworkRef)
	if err != nil {
		return false, err
	}
	return count > 0 && revision == receipt.Spec.PolicyRevision, nil
}

type ManagedBindingResolver struct {
	Customer    client.Client
	Service     *endpoints.Service
	ProjectName string
	Namespace   string
	Now         func() time.Time
}

func (resolver ManagedBindingResolver) Resolve(ctx context.Context, name string) (credentials.Binding, error) {
	binding := &connect.ConnectNetworkBinding{}
	if err := resolver.Customer.Get(ctx, client.ObjectKey{Namespace: resolver.Namespace, Name: name}, binding); err != nil {
		return credentials.Binding{}, err
	}
	if !binding.DeletionTimestamp.IsZero() {
		return credentials.Binding{}, credentials.ErrUnavailable
	}
	gateway := &connect.ConnectGateway{}
	if err := resolver.Customer.Get(ctx, client.ObjectKey{Namespace: resolver.Namespace, Name: binding.Spec.GatewayRef}, gateway); err != nil {
		return credentials.Binding{}, err
	}
	if !gateway.DeletionTimestamp.IsZero() || effectiveGatewayContract(gateway.Spec) != managedGatewayContract {
		return credentials.Binding{}, credentials.ErrUnavailable
	}
	connector := &connect.Connector{}
	if err := resolver.Customer.Get(ctx, client.ObjectKey{Namespace: resolver.Namespace, Name: binding.Spec.ConnectorRef}, connector); err != nil {
		return credentials.Binding{}, err
	}
	if !connector.DeletionTimestamp.IsZero() || !meta.IsStatusConditionTrue(connector.Status.Conditions, "Ready") {
		return credentials.Binding{}, credentials.ErrUnavailable
	}
	prefix, err := networkPrefix(ctx, resolver.Customer, resolver.Namespace, binding.Spec.NetworkRef)
	if err != nil {
		return credentials.Binding{}, err
	}
	var policies connect.ConnectConnectionPolicyList
	if err := resolver.Customer.List(ctx, &policies, client.InNamespace(resolver.Namespace)); err != nil {
		return credentials.Binding{}, err
	}
	revision, count, err := effectivePolicyRevision(policies.Items, connector, gateway, prefix, binding.Spec.NetworkRef)
	if err != nil || count == 0 {
		return credentials.Binding{}, fmt.Errorf("policy denied")
	}
	placement := &connect.ConnectGatewayPlacement{}
	if err := resolver.Customer.Get(ctx, client.ObjectKey{Namespace: resolver.Namespace, Name: binding.Status.SelectedPlacementRef}, placement); err != nil {
		return credentials.Binding{}, err
	}
	if placement.Spec.GatewayRef != gateway.Name || placement.Status.AssignmentRef == "" {
		return credentials.Binding{}, credentials.ErrUnavailable
	}
	endpoint := &connect.ConnectEndpoint{}
	if err := resolver.Service.Reconciler.Project.Get(ctx, client.ObjectKey{Namespace: resolver.Service.Namespace, Name: placement.Status.AssignmentRef}, endpoint); err != nil {
		return credentials.Binding{}, err
	}
	project := &unstructured.Unstructured{}
	project.SetGroupVersionKind(schema.GroupVersionKind{Group: "resourcemanager.miloapis.com", Version: "v1alpha1", Kind: "Project"})
	if err := resolver.Service.Root.Get(ctx, client.ObjectKey{Name: resolver.ProjectName}, project); err != nil {
		return credentials.Binding{}, err
	}
	network := &unstructured.Unstructured{}
	network.SetGroupVersionKind(schema.GroupVersionKind{Group: "networking.datumapis.com", Version: "v1alpha", Kind: "Network"})
	if err := resolver.Customer.Get(ctx, client.ObjectKey{Namespace: resolver.Namespace, Name: binding.Spec.NetworkRef}, network); err != nil {
		return credentials.Binding{}, err
	}
	if endpoint.Spec.CustomerProjectUID != string(project.GetUID()) || endpoint.Spec.GatewayUID != string(gateway.UID) || network.GetUID() == "" || !network.GetDeletionTimestamp().IsZero() || !endpoints.Ready(endpoint, resolver.Now(), 5*time.Minute) {
		return credentials.Binding{}, credentials.ErrUnavailable
	}
	vpc, err := resolver.Service.ResolveVPC(string(network.GetUID()), endpoint.Spec.Assignment.Cell)
	if err != nil {
		return credentials.Binding{}, err
	}
	if err := resolver.Service.ValidateBindingIdentity(ctx, string(binding.UID), string(network.GetUID()), endpoint.Spec.Assignment.Cell, vpc); err != nil {
		return credentials.Binding{}, err
	}
	return credentials.Binding{NetworkName: binding.Spec.NetworkRef, NetworkUID: string(network.GetUID()), VPC: vpc, Name: binding.Name, UID: string(binding.UID), Connector: connector.Name, PolicyRevision: revision, Placement: placement.Name, Endpoint: endpoint, NetworkPlan: credentials.NetworkPlan{DestinationPrefixes: []string{prefix}, MTU: 1280}}, nil
}
