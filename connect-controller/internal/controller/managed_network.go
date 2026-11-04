package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
)

const (
	legacyGatewayContract  = "legacy-v1"
	managedGatewayContract = "managed-network-v1"
	policyLabelPrefix      = "policy.connect.datum.net/"
)

type placementLocation struct {
	Name     string
	Topology map[string]string
	Ready    bool
}

// effectiveGatewayContract keeps stored preview resources working while every
// newly authored managed-network gateway carries an explicit discriminator.
func effectiveGatewayContract(spec connectv1alpha1.ConnectGatewaySpec) string {
	if spec.ContractVersion == "" {
		return legacyGatewayContract
	}
	return spec.ContractVersion
}

func validateManagedGatewaySpec(spec connectv1alpha1.ConnectGatewaySpec) error {
	if spec.NetworkRef == "" {
		return fmt.Errorf("networkRef is required")
	}
	if spec.Placement == nil {
		return fmt.Errorf("placement is required")
	}
	if spec.Placement.Availability.MinReady < 0 {
		return fmt.Errorf("placement.availability.minReady must be positive")
	}
	selector, err := metav1.LabelSelectorAsSelector(&spec.Placement.LocationSelector)
	if err != nil {
		return fmt.Errorf("invalid placement.locationSelector: %w", err)
	}
	if selector.Empty() {
		return fmt.Errorf("placement.locationSelector must not be empty")
	}
	return nil
}

func validateAuthorizationSelector(selector *metav1.LabelSelector, field string) error {
	if selector == nil || len(selector.MatchLabels)+len(selector.MatchExpressions) == 0 {
		return fmt.Errorf("%s must not be empty", field)
	}
	for key := range selector.MatchLabels {
		if !strings.HasPrefix(key, policyLabelPrefix) {
			return fmt.Errorf("%s key %q is outside %s*", field, key, policyLabelPrefix)
		}
	}
	for _, requirement := range selector.MatchExpressions {
		if !strings.HasPrefix(requirement.Key, policyLabelPrefix) {
			return fmt.Errorf("%s key %q is outside %s*", field, requirement.Key, policyLabelPrefix)
		}
		switch requirement.Operator {
		case metav1.LabelSelectorOpIn:
			if len(requirement.Values) == 0 {
				return fmt.Errorf("%s In requirement %q needs values", field, requirement.Key)
			}
		case metav1.LabelSelectorOpExists:
			if len(requirement.Values) != 0 {
				return fmt.Errorf("%s Exists requirement %q must not have values", field, requirement.Key)
			}
		default:
			return fmt.Errorf("%s operator %q is not supported", field, requirement.Operator)
		}
	}
	if _, err := metav1.LabelSelectorAsSelector(selector); err != nil {
		return fmt.Errorf("invalid %s: %w", field, err)
	}
	return nil
}

func validateConnectionPolicy(policy *connectv1alpha1.ConnectConnectionPolicy) error {
	hasRef := policy.Spec.GatewayRef != nil && policy.Spec.GatewayRef.Name != ""
	hasSelector := policy.Spec.GatewaySelector != nil
	if hasRef == hasSelector {
		return fmt.Errorf("exactly one of gatewayRef or gatewaySelector is required")
	}
	if hasSelector {
		if err := validateAuthorizationSelector(policy.Spec.GatewaySelector, "gatewaySelector"); err != nil {
			return err
		}
	}
	if err := validateAuthorizationSelector(&policy.Spec.ConnectorSelector, "connectorSelector"); err != nil {
		return err
	}
	if policy.Spec.Access.Permission != "Network" {
		return fmt.Errorf("access.permission must be Network")
	}
	return nil
}

func resolvePolicyGateways(policy *connectv1alpha1.ConnectConnectionPolicy, gateways []connectv1alpha1.ConnectGateway) ([]string, error) {
	if err := validateConnectionPolicy(policy); err != nil {
		return nil, err
	}
	if policy.Spec.GatewayRef != nil {
		for _, gateway := range gateways {
			if gateway.Namespace == policy.Namespace && gateway.Name == policy.Spec.GatewayRef.Name {
				return []string{gateway.Name}, nil
			}
		}
		return nil, nil
	}
	selector, _ := metav1.LabelSelectorAsSelector(policy.Spec.GatewaySelector)
	var resolved []string
	for _, gateway := range gateways {
		if gateway.Namespace == policy.Namespace && selector.Matches(labels.Set(gateway.Labels)) {
			resolved = append(resolved, gateway.Name)
		}
	}
	sort.Strings(resolved)
	return resolved, nil
}

func effectivePolicyRevision(policies []connectv1alpha1.ConnectConnectionPolicy, connector *connectv1alpha1.Connector, gateway *connectv1alpha1.ConnectGateway, networkPrefix string) (string, int, error) {
	var revisions []string
	for i := range policies {
		policy := &policies[i]
		if policy.Namespace != connector.Namespace {
			continue
		}
		if err := validateConnectionPolicy(policy); err != nil {
			continue
		}
		subject, _ := metav1.LabelSelectorAsSelector(&policy.Spec.ConnectorSelector)
		if !subject.Matches(labels.Set(connector.Labels)) {
			continue
		}
		matches := policy.Spec.GatewayRef != nil && policy.Spec.GatewayRef.Name == gateway.Name
		if policy.Spec.GatewaySelector != nil {
			gatewaySelector, _ := metav1.LabelSelectorAsSelector(policy.Spec.GatewaySelector)
			matches = gatewaySelector.Matches(labels.Set(gateway.Labels))
		}
		if matches {
			revisions = append(revisions, fmt.Sprintf("%s:%d:%s", policy.Name, policy.Generation, policy.Status.Revision))
		}
	}
	sort.Strings(revisions)
	if len(revisions) == 0 {
		return "", 0, nil
	}
	sum := sha256.Sum256([]byte(strings.Join(revisions, "\n") + "\nnetwork=" + networkPrefix))
	return hex.EncodeToString(sum[:]), len(revisions), nil
}

func placementName(gateway, location string) string {
	base := gateway + "-" + location
	if len(base) <= 63 {
		return base
	}
	sum := sha256.Sum256([]byte(base))
	return strings.TrimRight(base[:50], "-") + "-" + hex.EncodeToString(sum[:6])
}

func listPlacementLocations(ctx context.Context, c client.Client) ([]placementLocation, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{Group: "locations.miloapis.com", Version: "v1alpha1", Kind: "LocationList"})
	if err := c.List(ctx, list); err != nil {
		return nil, err
	}
	result := make([]placementLocation, 0, len(list.Items))
	for _, item := range list.Items {
		topology, _, _ := unstructured.NestedStringMap(item.Object, "spec", "topology")
		ready := false
		conditions, _, _ := unstructured.NestedSlice(item.Object, "status", "conditions")
		for _, raw := range conditions {
			condition, ok := raw.(map[string]interface{})
			if ok && condition["type"] == "Ready" && condition["status"] == "True" {
				ready = true
			}
		}
		result = append(result, placementLocation{Name: item.GetName(), Topology: topology, Ready: ready})
	}
	return result, nil
}

// reconcileManagedGatewayPlacements is kept separate from provider assignment:
// it owns only selector expansion and the bounded parent summary.
func reconcileManagedGatewayPlacements(ctx context.Context, c client.Client, gateway *connectv1alpha1.ConnectGateway, locations []placementLocation) error {
	if err := validateManagedGatewaySpec(gateway.Spec); err != nil {
		return updateManagedGatewayStatus(ctx, c, gateway, 0, 0, 0, false, err.Error())
	}
	selector, _ := metav1.LabelSelectorAsSelector(&gateway.Spec.Placement.LocationSelector)
	matched := map[string]placementLocation{}
	for _, location := range locations {
		if selector.Matches(labels.Set(location.Topology)) {
			matched[location.Name] = location
			placement := &connectv1alpha1.ConnectGatewayPlacement{}
			key := types.NamespacedName{Namespace: gateway.Namespace, Name: placementName(gateway.Name, location.Name)}
			err := c.Get(ctx, key, placement)
			if apierrors.IsNotFound(err) {
				placement.Namespace, placement.Name = key.Namespace, key.Name
				placement.Labels = map[string]string{"connect.datum.net/gateway": gateway.Name, "topology.datum.net/location": location.Name}
				placement.Spec = connectv1alpha1.ConnectGatewayPlacementSpec{GatewayRef: gateway.Name, LocationRef: location.Name}
				if err := controllerutil.SetControllerReference(gateway, placement, schemeForManagedNetwork()); err != nil {
					return err
				}
				if err := c.Create(ctx, placement); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
		}
	}
	var placements connectv1alpha1.ConnectGatewayPlacementList
	if err := c.List(ctx, &placements, client.InNamespace(gateway.Namespace), client.MatchingLabels{"connect.datum.net/gateway": gateway.Name}); err != nil {
		return err
	}
	var ready int32
	for i := range placements.Items {
		placement := &placements.Items[i]
		if placement.Spec.GatewayRef != gateway.Name {
			continue
		}
		if _, ok := matched[placement.Spec.LocationRef]; !ok {
			if err := c.Delete(ctx, placement); client.IgnoreNotFound(err) != nil {
				return err
			}
			continue
		}
		if meta.IsStatusConditionTrue(placement.Status.Conditions, "Ready") {
			ready++
		}
	}
	count := int32(len(matched))
	return updateManagedGatewayStatus(ctx, c, gateway, count, ready, count-ready, true, "selector resolved")
}

func updateManagedGatewayStatus(ctx context.Context, c client.Client, gateway *connectv1alpha1.ConnectGateway, matched, ready, unavailable int32, resolved bool, message string) error {
	gateway.Status.ObservedGeneration = gateway.Generation
	gateway.Status.ClassRef = ""
	gateway.Status.Phase = ""
	gateway.Status.IdleSince = nil
	gateway.Status.WorkloadRef = ""
	gateway.Status.EndpointID = ""
	gateway.Status.Matched, gateway.Status.Ready, gateway.Status.Unavailable = matched, ready, unavailable
	minimum := int32(1)
	if gateway.Spec.Placement != nil && gateway.Spec.Placement.Availability.MinReady > 0 {
		minimum = gateway.Spec.Placement.Availability.MinReady
	}
	set := func(kind string, status metav1.ConditionStatus, reason, msg string) {
		meta.SetStatusCondition(&gateway.Status.Conditions, metav1.Condition{Type: kind, Status: status, Reason: reason, Message: msg, ObservedGeneration: gateway.Generation})
	}
	if !resolved {
		set("SelectorResolved", metav1.ConditionFalse, "InvalidSelector", message)
		set("Ready", metav1.ConditionFalse, "SelectorInvalid", message)
		set("Progressing", metav1.ConditionFalse, "Blocked", message)
		set("Degraded", metav1.ConditionTrue, "InvalidConfiguration", message)
	} else {
		set("SelectorResolved", metav1.ConditionTrue, "Resolved", message)
		if ready >= minimum {
			set("Ready", metav1.ConditionTrue, "MinimumReady", "minimum ready placements satisfied")
		} else {
			set("Ready", metav1.ConditionFalse, "InsufficientReady", "waiting for ready placements")
		}
		if ready < matched {
			set("Progressing", metav1.ConditionTrue, "PlacementsPending", "placements are not all ready")
		} else {
			set("Progressing", metav1.ConditionFalse, "Complete", "all placements are ready")
		}
		if matched == 0 {
			set("Degraded", metav1.ConditionTrue, "NoMatchingLocations", "selector matched no locations")
		} else {
			set("Degraded", metav1.ConditionFalse, "Healthy", "selector and placements are healthy")
		}
	}
	// Enforce the fixed bounded condition set even after migration from legacy status.
	fixed := make([]metav1.Condition, 0, 4)
	for _, kind := range []string{"SelectorResolved", "Ready", "Progressing", "Degraded"} {
		if condition := meta.FindStatusCondition(gateway.Status.Conditions, kind); condition != nil {
			fixed = append(fixed, *condition)
		}
	}
	gateway.Status.Conditions = fixed
	return c.Status().Update(ctx, gateway)
}

func schemeForManagedNetwork() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = connectv1alpha1.AddToScheme(scheme)
	return scheme
}

func reconcileConnectionPolicy(ctx context.Context, c client.Client, policy *connectv1alpha1.ConnectConnectionPolicy) error {
	previousRevision := policy.Status.Revision
	policy.Status.ObservedGeneration = policy.Generation
	var gateways connectv1alpha1.ConnectGatewayList
	if err := c.List(ctx, &gateways, client.InNamespace(policy.Namespace)); err != nil {
		return err
	}
	resolved, err := resolvePolicyGateways(policy, gateways.Items)
	if err != nil {
		policy.Status.ResolvedGatewayCount = 0
		policy.Status.Revision = ""
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{Type: "Accepted", Status: metav1.ConditionFalse, Reason: "InvalidPolicy", Message: err.Error(), ObservedGeneration: policy.Generation})
		return c.Status().Update(ctx, policy)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("generation=%d\n%s", policy.Generation, strings.Join(resolved, "\n"))))
	policy.Status.ResolvedGatewayCount = int32(len(resolved))
	policy.Status.Revision = hex.EncodeToString(sum[:])
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Resolved", Message: fmt.Sprintf("resolved %d logical gateways", len(resolved)), ObservedGeneration: policy.Generation})
	if policy.Status.Revision != previousRevision {
		shown := resolved
		if len(shown) > 20 {
			shown = shown[:20]
		}
		event := &corev1.Event{ObjectMeta: metav1.ObjectMeta{GenerateName: policy.Name + "-gateway-set-", Namespace: policy.Namespace}, InvolvedObject: corev1.ObjectReference{APIVersion: connectv1alpha1.GroupVersion.String(), Kind: "ConnectConnectionPolicy", Namespace: policy.Namespace, Name: policy.Name, UID: policy.UID}, Reason: "GatewaySetChanged", Message: fmt.Sprintf("resolved gateway set changed: count=%d gateways=%s", len(resolved), strings.Join(shown, ",")), Source: corev1.EventSource{Component: "connect-controller"}, Type: corev1.EventTypeNormal, FirstTimestamp: metav1.Now(), LastTimestamp: metav1.Now(), Count: 1}
		if err := c.Create(ctx, event); err != nil {
			return err
		}
	}
	return c.Status().Update(ctx, policy)
}

func networkPrefix(ctx context.Context, c client.Client, namespace, name string) (string, error) {
	network := &unstructured.Unstructured{}
	network.SetGroupVersionKind(schema.GroupVersionKind{Group: "networking.datumapis.com", Version: "v1alpha", Kind: "Network"})
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, network); err != nil {
		return "", err
	}
	prefix, found, err := unstructured.NestedString(network.Object, "status", "ipam", "ipv6Prefix")
	if err != nil {
		return "", err
	}
	if !found || prefix == "" {
		return "", fmt.Errorf("Network %s has no allocated IPv6 prefix", name)
	}
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil || !parsed.Addr().Is6() {
		return "", fmt.Errorf("Network %s published invalid IPv6 prefix", name)
	}
	return parsed.Masked().String(), nil
}

func reconcileManagedNetworkBinding(ctx context.Context, c client.Client, binding *connectv1alpha1.ConnectNetworkBinding, gateway *connectv1alpha1.ConnectGateway) error {
	binding.Status.EndpointID = ""
	binding.Status.AssignedAddress = ""
	binding.Status.PeerAddress = ""
	binding.Status.Routes = nil
	binding.Status.RelayURLs = nil
	setCondition := func(status metav1.ConditionStatus, reason, message string) error {
		binding.Status.ObservedGeneration = binding.Generation
		meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{Type: "Ready", Status: status, Reason: reason, Message: message, ObservedGeneration: binding.Generation})
		return c.Status().Update(ctx, binding)
	}
	var connector connectv1alpha1.Connector
	if err := c.Get(ctx, types.NamespacedName{Namespace: binding.Namespace, Name: binding.Spec.ConnectorRef}, &connector); err != nil {
		if apierrors.IsNotFound(err) {
			return setCondition(metav1.ConditionFalse, "ConnectorNotFound", "referenced Connector does not exist")
		}
		return err
	}
	var placements connectv1alpha1.ConnectGatewayPlacementList
	if err := c.List(ctx, &placements, client.InNamespace(binding.Namespace), client.MatchingLabels{"connect.datum.net/gateway": gateway.Name}); err != nil {
		return err
	}
	sort.Slice(placements.Items, func(i, j int) bool {
		return placements.Items[i].Spec.LocationRef < placements.Items[j].Spec.LocationRef
	})
	selected := ""
	for i := range placements.Items {
		placement := &placements.Items[i]
		if placement.Spec.GatewayRef == gateway.Name && meta.IsStatusConditionTrue(placement.Status.Conditions, "Ready") {
			selected = placement.Name
			break
		}
	}
	if selected == "" {
		return setCondition(metav1.ConditionFalse, "NoReadyPlacement", "logical gateway has no ready placement")
	}
	prefix, err := networkPrefix(ctx, c, binding.Namespace, gateway.Spec.NetworkRef)
	if err != nil {
		return setCondition(metav1.ConditionFalse, "NetworkNotReady", err.Error())
	}
	var policies connectv1alpha1.ConnectConnectionPolicyList
	if err := c.List(ctx, &policies, client.InNamespace(binding.Namespace)); err != nil {
		return err
	}
	revision, count, err := effectivePolicyRevision(policies.Items, &connector, gateway, prefix)
	if err != nil {
		return setCondition(metav1.ConditionFalse, "PolicyInvalid", err.Error())
	}
	if count == 0 {
		return setCondition(metav1.ConditionFalse, "PolicyDenied", "no applicable connection policy grants access")
	}
	binding.Status.SelectedPlacementRef = selected
	binding.Status.EffectivePolicyRevision = revision
	if binding.Status.NetworkPlan == nil {
		binding.Status.NetworkPlan = &connectv1alpha1.ConnectNetworkPlanSummary{}
	}
	// The /96 is authority allocated and is filled only after the credential
	// issuer returns it. Never synthesize it from a name or Network prefix.
	binding.Status.NetworkPlan.DestinationPrefixes = []string{prefix}
	binding.Status.NetworkPlan.MTU = 1280
	if binding.Status.NetworkPlan.ExpectedPrefix == "" {
		return setCondition(metav1.ConditionTrue, "Resolved", "placement and policy are current; the authority assigns the prefix when credentials are minted")
	}
	return setCondition(metav1.ConditionTrue, "Resolved", "placement, policy, and nonsecret network plan are current")
}
