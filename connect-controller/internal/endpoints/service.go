package endpoints

import (
	"context"
	"fmt"
	"sort"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const MetroKey = "topology.datum.net/metro"

func (s *Service) ValidateBindingIdentity(ctx context.Context, bindingUID, networkUID, cell string, vpc connect.EndpointVPCReference) error {
	var receipts connect.ConnectGrantList
	if err := s.Reconciler.Project.List(ctx, &receipts, client.InNamespace(s.Namespace)); err != nil {
		return err
	}
	for _, receipt := range receipts.Items {
		if receipt.Spec.BindingUID != bindingUID {
			continue
		}
		if receipt.Spec.NetworkUID != networkUID || (receipt.Spec.Cell == cell && receipt.Spec.VPC != vpc) {
			return fmt.Errorf("network identity changed; recreate the binding to authorize the replacement")
		}
	}
	return nil
}

func (s *Service) ResolveVPC(networkUID, cell string) (connect.EndpointVPCReference, error) {
	var result connect.EndpointVPCReference
	for _, mapping := range s.Reachability {
		if mapping.NetworkUID == networkUID && mapping.Cell == cell {
			if result.UID != "" {
				return result, fmt.Errorf("ambiguous network reachability")
			}
			result = mapping.VPC
		}
	}
	if result.UID == "" || result.Name == "" || result.Namespace == "" {
		return result, fmt.Errorf("selected cell does not support network")
	}
	return result, nil
}

type Capacity struct {
	Metro      string                     `json:"metro"`
	Assignment connect.EndpointAssignment `json:"assignment"`
}

type Reachability struct {
	NetworkUID string                       `json:"networkUID"`
	Cell       string                       `json:"cell"`
	VPC        connect.EndpointVPCReference `json:"vpcRef"`
}

type CellConfig struct {
	Kubeconfig      string `json:"kubeconfig"`
	GrantKubeconfig string `json:"grantKubeconfig,omitempty"`
}

type Config struct {
	Reachability []Reachability        `json:"reachability"`
	Capacity     []Capacity            `json:"capacity"`
	Cells        map[string]CellConfig `json:"cells"`
	ProbeURL     string                `json:"probeURL"`
}

type Service struct {
	Reachability []Reachability
	Reconciler   *Reconciler
	Root         client.Client
	Customer     func(context.Context, string) (client.Client, error)
	Namespace    string
	Domain       string
	Capacity     []Capacity
	Provision    bool
}

func (s *Service) Sync(ctx context.Context, customer client.Client, projectName string, gateway *connect.ConnectGateway, locations map[string]string) error {
	metros, err := Metros(locations)
	if err != nil {
		return err
	}
	project := object(schema.GroupVersionKind{Group: "resourcemanager.miloapis.com", Version: "v1alpha1", Kind: "Project"}, "", projectName)
	if err := s.Root.Get(ctx, client.ObjectKeyFromObject(project), project); err != nil {
		return err
	}
	if project.GetUID() == "" || gateway.UID == "" {
		return fmt.Errorf("project and gateway UIDs are required")
	}
	if !gateway.DeletionTimestamp.IsZero() {
		metros = nil
	}
	desired := map[string]*connect.ConnectEndpoint{}
	for _, metro := range metros {
		key := client.ObjectKey{Namespace: s.Namespace, Name: Name(string(project.GetUID()), string(gateway.UID), metro)}
		endpoint := &connect.ConnectEndpoint{}
		err := s.Reconciler.Project.Get(ctx, key, endpoint)
		if apierrors.IsNotFound(err) && s.Provision {
			endpoint, err = Reserve(ctx, s.Reconciler.Project, s.Namespace, s.Domain, connect.ConnectEndpointSpec{CustomerProjectUID: string(project.GetUID()), GatewayUID: string(gateway.UID), Metro: metro, CustomerProject: projectName, GatewayNamespace: gateway.Namespace, GatewayName: gateway.Name})
		}
		if err != nil {
			return err
		}
		if endpoint.Spec.Lifecycle == "Retired" && endpoint.Status.Phase == "Retired" && s.Provision {
			endpoint.Spec.Lifecycle = "Active"
			if err := s.Reconciler.Project.Update(ctx, endpoint); err != nil {
				return err
			}
		}
		if endpoint.Spec.Lifecycle != "Active" {
			return fmt.Errorf("endpoint is draining or retired")
		}
		if endpoint.Spec.Assignment.Cell == "" {
			for _, capacity := range s.Capacity {
				if capacity.Metro == metro {
					endpoint.Spec.Assignment = capacity.Assignment
					if err := s.Reconciler.Project.Update(ctx, endpoint); err != nil {
						return err
					}
					break
				}
			}
		}
		desired[metro] = endpoint
	}
	var existing connect.ConnectEndpointList
	if err := s.Reconciler.Project.List(ctx, &existing, client.InNamespace(s.Namespace)); err != nil {
		return err
	}
	for index := range existing.Items {
		endpoint := &existing.Items[index]
		if endpoint.Spec.CustomerProjectUID != string(project.GetUID()) || endpoint.Spec.GatewayUID != string(gateway.UID) || endpoint.Spec.Lifecycle != "Active" {
			continue
		}
		if _, retained := desired[endpoint.Spec.Metro]; !retained {
			endpoint.Spec.Lifecycle = "Deleting"
			if err := s.Reconciler.Project.Update(ctx, endpoint); err != nil {
				return err
			}
		}
	}
	var placements connect.ConnectGatewayPlacementList
	if err := customer.List(ctx, &placements, client.InNamespace(gateway.Namespace), client.MatchingLabels{"connect.datum.net/gateway": gateway.Name}); err != nil {
		return err
	}
	for index := range placements.Items {
		placement := &placements.Items[index]
		if placement.Spec.GatewayRef != gateway.Name {
			continue
		}
		endpoint := desired[locations[placement.Spec.LocationRef]]
		condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: "EndpointPending", Message: "waiting for managed endpoint", ObservedGeneration: placement.Generation}
		placement.Status.AssignmentRef = ""
		placement.Status.Hostname = ""
		placement.Status.Metro = locations[placement.Spec.LocationRef]
		if endpoint != nil {
			placement.Status.AssignmentRef = endpoint.Name
			placement.Status.Hostname = endpoint.Spec.Hostname
			placement.Status.CertificateNotAfter = endpoint.Status.NotAfter
			if Ready(endpoint, s.Reconciler.Now(), s.Reconciler.ExpiryMargin) {
				condition.Status = metav1.ConditionTrue
				condition.Reason = "EndpointReady"
				condition.Message = "managed endpoint verified"
			}
		}
		placement.Status.ObservedGeneration = placement.Generation
		meta.SetStatusCondition(&placement.Status.Conditions, condition)
		if err := customer.Status().Update(ctx, placement); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Sweep(ctx context.Context) error {
	var endpoints connect.ConnectEndpointList
	if err := s.Reconciler.Project.List(ctx, &endpoints, client.InNamespace(s.Namespace)); err != nil {
		return err
	}
	sort.Slice(endpoints.Items, func(left, right int) bool { return endpoints.Items[left].Name < endpoints.Items[right].Name })
	for index := range endpoints.Items {
		endpoint := &endpoints.Items[index]
		if endpoint.Spec.Lifecycle == "Retired" {
			continue
		}
		if endpoint.Spec.Lifecycle == "Active" {
			gone, err := s.ownerGone(ctx, endpoint)
			if err != nil {
				log.FromContext(ctx).Error(err, "check endpoint owner", "endpoint", endpoint.Name)
			} else if gone {
				endpoint.Spec.Lifecycle = "Deleting"
				if err := s.Reconciler.Project.Update(ctx, endpoint); err != nil {
					continue
				}
			}
		}
		if endpoint.Spec.Assignment.Cell == "" && endpoint.Spec.Lifecycle == "Active" {
			continue
		}
		if err := s.Reconciler.Reconcile(ctx, client.ObjectKeyFromObject(endpoint)); err != nil {
			log.FromContext(ctx).V(1).Info("managed endpoint pending", "endpoint", endpoint.Name, "reason", err.Error())
		}
	}
	return nil
}

func (s *Service) ownerGone(ctx context.Context, endpoint *connect.ConnectEndpoint) (bool, error) {
	project := object(schema.GroupVersionKind{Group: "resourcemanager.miloapis.com", Version: "v1alpha1", Kind: "Project"}, "", endpoint.Spec.CustomerProject)
	if err := s.Root.Get(ctx, client.ObjectKeyFromObject(project), project); err != nil {
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	}
	if string(project.GetUID()) != endpoint.Spec.CustomerProjectUID || !project.GetDeletionTimestamp().IsZero() {
		return true, nil
	}
	customer, err := s.Customer(ctx, endpoint.Spec.CustomerProject)
	if err != nil {
		return false, err
	}
	gateway := &connect.ConnectGateway{}
	if err := customer.Get(ctx, client.ObjectKey{Namespace: endpoint.Spec.GatewayNamespace, Name: endpoint.Spec.GatewayName}, gateway); err != nil {
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	}
	return string(gateway.UID) != endpoint.Spec.GatewayUID || !gateway.DeletionTimestamp.IsZero(), nil
}

func (s *Service) Start(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.Sweep(ctx); err != nil {
			log.FromContext(ctx).Error(err, "managed endpoint sweep")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Service) NeedLeaderElection() bool { return true }

func LocationMetros(items []unstructured.Unstructured) map[string]string {
	result := map[string]string{}
	for _, location := range items {
		metro, _, _ := unstructured.NestedString(location.Object, "spec", "topology", MetroKey)
		result[location.GetName()] = metro
	}
	return result
}
