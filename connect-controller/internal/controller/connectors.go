package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
)

type ConnectReconciler struct {
	mgr         mcmanager.Manager
	kind        string
	classClient client.Client
	Identity    ConnectorIdentityConfig
}

// +kubebuilder:rbac:groups=connect.datumapis.com,resources=connectorclasses;connectoradvertisements;connectgateways;connectnetworkbindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=connect.datumapis.com,resources=connectorenrollments,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups=connect.datumapis.com,resources=connectors,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=connect.datumapis.com,resources=connectors/finalizers,verbs=update
// +kubebuilder:rbac:groups=connect.datumapis.com,resources=connectorclasses/status;connectors/status;connectoradvertisements/status;connectgateways/status;connectnetworkbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=compute.datumapis.com,resources=workloads,verbs=get;create;update;patch
// +kubebuilder:rbac:groups=core,resources=configmaps;secrets,verbs=get;create;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=serviceaccounts,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=policybindings,verbs=get;create;delete
// +kubebuilder:rbac:groups=identity.miloapis.com,resources=serviceaccountkeys,verbs=get;list;watch;create;delete

func (r *ConnectReconciler) SetupWithManager(mgr mcmanager.Manager) error {
	local := mgr.GetLocalManager()
	if err := builder.ControllerManagedBy(local).Named("connectorclass").For(&connectv1alpha1.ConnectorClass{}).Complete(&ClassReconciler{client: local.GetClient()}); err != nil {
		return fmt.Errorf("register ConnectorClass controller: %w", err)
	}
	for _, item := range []struct {
		name string
		obj  client.Object
	}{
		{"connector", &connectv1alpha1.Connector{}},
		{"connectorenrollment", &connectv1alpha1.ConnectorEnrollment{}},
		{"connectoradvertisement", &connectv1alpha1.ConnectorAdvertisement{}},
		{"connectgateway", &connectv1alpha1.ConnectGateway{}},
		{"connectnetworkbinding", &connectv1alpha1.ConnectNetworkBinding{}},
	} {
		builder := mcbuilder.ControllerManagedBy(mgr).Named(item.name).For(item.obj,
			mcbuilder.WithEngageWithLocalCluster(false))
		if item.name == "connector" {
			builder = builder.Owns(&coordinationv1.Lease{})
		}
		if err := builder.Complete(&ConnectReconciler{mgr: mgr, kind: item.name, classClient: local.GetClient(), Identity: r.Identity}); err != nil {
			return fmt.Errorf("register %s controller: %w", item.name, err)
		}
	}
	return nil
}

func (r *ConnectReconciler) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("projectCluster", req.ClusterName)
	cl, err := r.mgr.GetCluster(ctx, req.ClusterName)
	if err != nil {
		return ctrl.Result{}, err
	}
	c := cl.GetClient()
	key := req.NamespacedName
	// Each registered controller reconciles its own kind; absent objects are normal.
	switch r.kind {
	case "connector":
		var obj connectv1alpha1.Connector
		if err := c.Get(ctx, key, &obj); err != nil {
			if apierrors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		var enrollment connectv1alpha1.ConnectorEnrollment
		var enrollmentPtr *connectv1alpha1.ConnectorEnrollment
		if err := c.Get(ctx, key, &enrollment); err == nil {
			enrollmentPtr = &enrollment
		} else if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		var identityClient client.Client
		if enrollmentPtr != nil || controllerutil.ContainsFinalizer(&obj, connectorIdentityFinalizer) {
			if r.Identity.Project == "" || r.Identity.Project == req.ClusterName.String() {
				return ctrl.Result{}, fmt.Errorf("platform identity project must be configured and distinct from consumer project %q", req.ClusterName)
			}
			identityCluster, err := r.mgr.GetCluster(ctx, multicluster.ClusterName(r.Identity.Project))
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("get platform identity project %q: %w", r.Identity.Project, err)
			}
			identityClient = identityCluster.GetClient()
		}
		if err := reconcileConnector(ctx, c, r.classClient, identityClient, r.Identity, req.ClusterName.String(), &obj, enrollmentPtr); err != nil {
			logger.Error(err, "reconcile Connector")
			return ctrl.Result{}, err
		}
		// Recheck expiry even if no Lease update arrives at the exact TTL edge.
		// Lease renewals also enqueue the owning Connector through Owns above.
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	case "connectorenrollment":
		var enrollment connectv1alpha1.ConnectorEnrollment
		if err := c.Get(ctx, key, &enrollment); err != nil {
			if apierrors.IsNotFound(err) {
				// ConnectorEnrollment is required to be same-name. A deletion
				// event must immediately reconcile the Connector so its grants
				// and credentials are revoked rather than waiting for polling.
				var obj connectv1alpha1.Connector
				if err := c.Get(ctx, key, &obj); err != nil {
					if apierrors.IsNotFound(err) {
						return ctrl.Result{}, nil
					}
					return ctrl.Result{}, err
				}
				if !controllerutil.ContainsFinalizer(&obj, connectorIdentityFinalizer) {
					return ctrl.Result{}, nil
				}
				if r.Identity.Project == "" || r.Identity.Project == req.ClusterName.String() {
					return ctrl.Result{}, fmt.Errorf("platform identity project must be configured and distinct from consumer project %q", req.ClusterName)
				}
				identityCluster, err := r.mgr.GetCluster(ctx, multicluster.ClusterName(r.Identity.Project))
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("get platform identity project %q: %w", r.Identity.Project, err)
				}
				if err := reconcileConnector(ctx, c, r.classClient, identityCluster.GetClient(), r.Identity, req.ClusterName.String(), &obj, nil); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
			}
			return ctrl.Result{}, err
		}
		var obj connectv1alpha1.Connector
		if err := c.Get(ctx, types.NamespacedName{Name: enrollment.Spec.ConnectorRef.Name, Namespace: enrollment.Namespace}, &obj); err != nil {
			return ctrl.Result{}, err
		}
		if r.Identity.Project == "" || r.Identity.Project == req.ClusterName.String() {
			return ctrl.Result{}, fmt.Errorf("platform identity project must be configured and distinct from consumer project %q", req.ClusterName)
		}
		identityCluster, err := r.mgr.GetCluster(ctx, multicluster.ClusterName(r.Identity.Project))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("get platform identity project %q: %w", r.Identity.Project, err)
		}
		if err := reconcileConnector(ctx, c, r.classClient, identityCluster.GetClient(), r.Identity, req.ClusterName.String(), &obj, &enrollment); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	case "connectoradvertisement":
		var obj connectv1alpha1.ConnectorAdvertisement
		if err := c.Get(ctx, key, &obj); err != nil {
			if apierrors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		if err := reconcileAdvertisement(ctx, c, &obj); err != nil {
			logger.Error(err, "reconcile ConnectorAdvertisement")
			return ctrl.Result{}, err
		}
		if condition := meta.FindStatusCondition(obj.Status.Conditions, "Accepted"); condition != nil && condition.Reason == "ConnectorNotFound" || condition != nil && condition.Reason == "ConnectorNotReady" {
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
	case "connectgateway":
		var obj connectv1alpha1.ConnectGateway
		if err := c.Get(ctx, key, &obj); err != nil {
			if apierrors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		if err := reconcileGateway(ctx, c, string(req.ClusterName), &obj); err != nil {
			logger.Error(err, "reconcile ConnectGateway")
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 20 * time.Second}, nil
	case "connectnetworkbinding":
		var obj connectv1alpha1.ConnectNetworkBinding
		if err := c.Get(ctx, key, &obj); err != nil {
			if apierrors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		if err := reconcileNetworkBinding(ctx, c, string(req.ClusterName), &obj); err != nil {
			logger.Error(err, "reconcile ConnectNetworkBinding")
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 20 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

type ClassReconciler struct{ client client.Client }

func (r *ClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj connectv1alpha1.ConnectorClass
	if err := r.client.Get(ctx, req.NamespacedName, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if err := reconcileClass(ctx, r.client, &obj); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func reconcileClass(ctx context.Context, c client.Client, obj *connectv1alpha1.ConnectorClass) error {
	before := obj.Status.DeepCopy()
	status, reason, message := metav1.ConditionTrue, "Valid", "ConnectorClass is valid"
	if len(obj.Spec.Transports) == 0 {
		status, reason, message = metav1.ConditionFalse, "NoTransport", "at least one transport must be configured"
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: "Ready", Status: status, Reason: reason, Message: message, ObservedGeneration: obj.Generation})
	obj.Status.ObservedGeneration = obj.Generation
	if reflect.DeepEqual(before, &obj.Status) {
		return nil
	}
	return c.Status().Update(ctx, obj)
}

func reconcileConnector(ctx context.Context, c, classClient, identityClient client.Client, identityConfig ConnectorIdentityConfig, consumerProject string, obj *connectv1alpha1.Connector, enrollment *connectv1alpha1.ConnectorEnrollment) error {
	if !obj.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(obj, connectorIdentityFinalizer) {
			if identityClient == nil {
				return fmt.Errorf("platform identity client is required to finalize Connector credentials")
			}
			complete, err := cleanupConnectorIdentity(ctx, c, identityClient, identityConfig, obj, true)
			if err != nil {
				return err
			}
			if !complete {
				return nil
			}
			controllerutil.RemoveFinalizer(obj, connectorIdentityFinalizer)
			return c.Update(ctx, obj)
		}
		return nil
	}
	if enrollment != nil && !controllerutil.ContainsFinalizer(obj, connectorIdentityFinalizer) {
		if identityClient == nil {
			return fmt.Errorf("platform identity client is required for Connector authentication")
		}
		controllerutil.AddFinalizer(obj, connectorIdentityFinalizer)
		if err := c.Update(ctx, obj); err != nil {
			return err
		}
	}
	before := obj.Status.DeepCopy()
	var reconcileErr error
	accepted, acceptedReason, acceptedMessage := metav1.ConditionTrue, "Accepted", "Connector class and identity are valid"
	if _, err := hex.DecodeString(obj.Spec.PublicKey); err != nil || len(obj.Spec.PublicKey) != 64 {
		accepted, acceptedReason, acceptedMessage = metav1.ConditionFalse, "InvalidPublicKey", "publicKey must be a 32-byte hexadecimal iroh public key"
	} else if enrollment != nil {
		if err := validateConnectorAuthentication(obj, enrollment); err != nil {
			accepted, acceptedReason, acceptedMessage = metav1.ConditionFalse, "InvalidAuthentication", err.Error()
		}
	}
	if accepted == metav1.ConditionTrue {
		if errs := validation.IsDNS1123Subdomain(obj.Spec.ClassRef); len(errs) > 0 {
			accepted, acceptedReason, acceptedMessage = metav1.ConditionFalse, "InvalidClassReference", "classRef must be a DNS subdomain resource name"
		} else {
			var class connectv1alpha1.ConnectorClass
			err := classClient.Get(ctx, types.NamespacedName{Name: obj.Spec.ClassRef}, &class)
			if apierrors.IsNotFound(err) {
				accepted, acceptedReason, acceptedMessage = metav1.ConditionFalse, "ClassNotFound", "referenced ConnectorClass does not exist in the management cluster"
			} else if err != nil {
				return err
			} else if !contains(class.Spec.Transports, "masque-v1") {
				accepted, acceptedReason, acceptedMessage = metav1.ConditionFalse, "TransportUnsupported", "ConnectorClass does not advertise masque-v1"
			}
		}
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: "Accepted", Status: accepted, Reason: acceptedReason, Message: acceptedMessage, ObservedGeneration: obj.Generation})
	var lease *coordinationv1.Lease
	if accepted == metav1.ConditionTrue {
		var err error
		lease, err = ensureConnectorLease(ctx, c, obj)
		if err != nil {
			return err
		}
		obj.Status.LeaseRef = lease.Name
	}
	identityReady := accepted == metav1.ConditionTrue
	identityStatus, identityReason, identityMessage := metav1.ConditionFalse, "NotAccepted", "waiting for a valid Connector configuration"
	if accepted == metav1.ConditionTrue {
		if enrollment == nil {
			if controllerutil.ContainsFinalizer(obj, connectorIdentityFinalizer) {
				// Do not continue advertising revoked provider identifiers in
				// status after the protected enrollment has disappeared.
				obj.Status.Authentication = nil
				if identityClient == nil {
					identityReady, identityReason, identityMessage = false, "IdentityConfigurationMissing", "platform identity project is not configured"
				} else {
					complete, err := cleanupConnectorIdentity(ctx, c, identityClient, identityConfig, obj, false)
					if err != nil {
						reconcileErr = err
						identityReady, identityStatus, identityReason, identityMessage = false, metav1.ConditionFalse, "RevocationFailed", "protected Connector enrollment is missing and credential revocation failed"
					} else if !complete {
						identityReady, identityStatus, identityReason, identityMessage = false, metav1.ConditionFalse, "RevocationPending", "protected Connector enrollment is missing; platform credential and grant deletion is pending"
					} else {
						identityReady, identityStatus, identityReason, identityMessage = false, metav1.ConditionFalse, "EnrollmentMissing", "protected Connector enrollment is missing; platform credentials and grants are revoked; platform recovery is required"
					}
				}
			} else {
				identityStatus, identityReason, identityMessage = metav1.ConditionUnknown, "LegacyCredentials", "Connector uses externally supplied migration credentials"
			}
		} else {
			var err error
			if identityClient == nil {
				identityReady, identityReason, identityMessage = false, "IdentityConfigurationMissing", "platform identity project is not configured"
			} else {
				identityReady, identityReason, identityMessage, err = ensureConnectorIdentity(ctx, c, identityClient, identityConfig, consumerProject, obj, enrollment)
			}
			if identityReady {
				identityStatus = metav1.ConditionTrue
			}
			if err != nil {
				reconcileErr = err
			}
		}
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: "AuthenticationReady", Status: identityStatus, Reason: identityReason, Message: identityMessage, ObservedGeneration: obj.Generation})
	ready, readyReason, readyMessage := metav1.ConditionFalse, "NotReady", "waiting for a valid Connector configuration"
	if accepted == metav1.ConditionTrue && identityReady && lease != nil {
		if lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil {
			readyReason, readyMessage = "AgentOffline", "Connector has not renewed its liveness lease"
		} else {
			expiresAt := lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second)
			if time.Now().Before(expiresAt) {
				ready, readyReason, readyMessage = metav1.ConditionTrue, "ConnectorReady", "Connector has a current liveness lease"
			} else {
				readyReason, readyMessage = "AgentOffline", "Connector liveness lease has expired"
			}
		}
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: "Ready", Status: ready, Reason: readyReason, Message: readyMessage, ObservedGeneration: obj.Generation})
	obj.Status.ObservedGeneration = obj.Generation
	if reflect.DeepEqual(before, &obj.Status) {
		return reconcileErr
	}
	if err := c.Status().Update(ctx, obj); err != nil {
		return err
	}
	return reconcileErr
}

func ensureConnectorLease(ctx context.Context, c client.Client, connector *connectv1alpha1.Connector) (*coordinationv1.Lease, error) {
	// Keep Connect leases distinct from the legacy networking.datumapis.com
	// Connector controller, which historically used the Connector name for its
	// Lease. The two APIs can coexist during migration and cannot share owner refs.
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: connectorLeaseName(connector.Name), Namespace: connector.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, c, lease, func() error {
		if err := controllerutil.SetControllerReference(connector, lease, schemeForConnector()); err != nil {
			return err
		}
		if lease.Spec.LeaseDurationSeconds == nil || *lease.Spec.LeaseDurationSeconds == 0 {
			duration := int32(30)
			lease.Spec.LeaseDurationSeconds = &duration
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lease, nil
}

func connectorLeaseName(connectorName string) string {
	// Hash the Connector name so the derived Lease is DNS-safe, short, and
	// collision-resistant even when a user-supplied Connector name is 63 chars.
	sum := sha256.Sum256([]byte(connectorName))
	return "connect-lease-" + hex.EncodeToString(sum[:8])
}

func schemeForConnector() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = coordinationv1.AddToScheme(s)
	_ = iamv1alpha1.AddToScheme(s)
	_ = identityv1alpha1.AddToScheme(s)
	_ = connectv1alpha1.AddToScheme(s)
	return s
}

func reconcileAdvertisement(ctx context.Context, c client.Client, obj *connectv1alpha1.ConnectorAdvertisement) error {
	before := obj.Status.DeepCopy()
	status, reason, message := metav1.ConditionTrue, "Accepted", "advertisement is accepted"
	var connector connectv1alpha1.Connector
	err := c.Get(ctx, types.NamespacedName{Name: obj.Spec.ConnectorRef}, &connector)
	if apierrors.IsNotFound(err) {
		status, reason, message = metav1.ConditionFalse, "ConnectorNotFound", "referenced Connector does not exist in this project"
	} else if err != nil {
		return err
	} else if !meta.IsStatusConditionTrue(connector.Status.Conditions, "Ready") {
		status, reason, message = metav1.ConditionFalse, "ConnectorNotReady", "referenced Connector is not ready"
	}
	for _, service := range obj.Spec.Services {
		if service.Port < 1 || service.Port > 65535 || (service.Protocol != "TCP" && service.Protocol != "UDP") {
			status, reason, message = metav1.ConditionFalse, "InvalidService", "services must use TCP or UDP and ports from 1 to 65535"
			break
		}
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: "Accepted", Status: status, Reason: reason, Message: message, ObservedGeneration: obj.Generation})
	obj.Status.ObservedGeneration = obj.Generation
	if reflect.DeepEqual(before, &obj.Status) {
		return nil
	}
	return c.Status().Update(ctx, obj)
}

func reconcileGateway(ctx context.Context, c client.Client, project string, obj *connectv1alpha1.ConnectGateway) error {
	before := obj.Status.DeepCopy()
	status, reason, message := metav1.ConditionUnknown, "Provisioning", "gateway resources are being reconciled"
	if err := validateGatewaySpec(obj.Spec); err != nil {
		status, reason, message = metav1.ConditionFalse, "InvalidSpec", err.Error()
	} else if err := reconcileGatewayResources(ctx, c, project, obj); err != nil {
		var capacityError *gatewayPeerRouteCapacityError
		if errors.As(err, &capacityError) {
			status, reason, message = metav1.ConditionFalse, "PeerRouteCapacityExceeded", capacityError.Error()
		} else {
			return err
		}
	} else {
		workload := &unstructured.Unstructured{}
		workload.SetGroupVersionKind(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"})
		if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(obj.Name, "workload"), Namespace: obj.Namespace}, workload); err != nil {
			return err
		}
		if gatewayWorkloadReady(workload) && gatewayWorkloadConfigApplied(ctx, c, obj, workload) {
			status, reason, message = metav1.ConditionTrue, "GatewayAvailable", "gateway Workload is available in the requested VPC"
		} else {
			status, reason, message = metav1.ConditionUnknown, "WorkloadProvisioning", "waiting for the Compute gateway Workload to apply its current configuration and become available"
		}
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: "Ready", Status: status, Reason: reason, Message: message, ObservedGeneration: obj.Generation})
	obj.Status.ObservedGeneration = obj.Generation
	if reflect.DeepEqual(before, &obj.Status) {
		return nil
	}
	return c.Status().Update(ctx, obj)
}

func validateGatewaySpec(spec connectv1alpha1.ConnectGatewaySpec) error {
	for name, value := range map[string]string{"networkRef": spec.NetworkRef, "locationRef": spec.LocationRef, "image": spec.Image} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if len(spec.Routes) == 0 || len(spec.Routes) > 32 {
		return fmt.Errorf("routes must contain between 1 and 32 IPv6 prefixes")
	}
	if len(spec.RelayURLs) > 5 {
		return fmt.Errorf("relayURLs cannot contain more than 5 entries")
	}
	seenRelays := map[string]bool{}
	for _, relay := range spec.RelayURLs {
		parsed, err := url.Parse(relay)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("relay URL %q must be an HTTPS URL without credentials, query, or fragment", relay)
		}
		if seenRelays[relay] {
			return fmt.Errorf("relay URL %q is duplicated", relay)
		}
		seenRelays[relay] = true
	}
	parsed := make([]netip.Prefix, 0, len(spec.Routes))
	for _, route := range spec.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return fmt.Errorf("route %q must be a valid IPv6 prefix", route)
		}
		if prefix.Bits() < 2 {
			return fmt.Errorf("route %q is too broad for a relay-only gateway", route)
		}
		for _, previous := range parsed {
			if previous.Contains(prefix.Addr()) || prefix.Contains(previous.Addr()) {
				return fmt.Errorf("routes %q and %q overlap", previous, prefix)
			}
		}
		parsed = append(parsed, prefix)
	}
	return nil
}

func reconcileGatewayResources(ctx context.Context, c client.Client, project string, gateway *connectv1alpha1.ConnectGateway) error {
	scheme := schemeForGateway()
	secretName := gatewayChildName(gateway.Name, "identity")
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: gateway.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, c, secret, func() error {
		if len(secret.Data["key"]) != ed25519.SeedSize {
			seed := make([]byte, ed25519.SeedSize)
			if _, err := rand.Read(seed); err != nil {
				return err
			}
			secret.Data = map[string][]byte{"key": seed}
		}
		secret.Type = corev1.SecretTypeOpaque
		return controllerutil.SetControllerReference(gateway, secret, scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile gateway identity Secret: %w", err)
	}
	seed := secret.Data["key"]
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	endpointID := hex.EncodeToString(publicKey)
	gateway.Status.EndpointID = endpointID
	peerGrants, err := readyGatewayGrants(ctx, c, project, gateway, endpointID)
	if err != nil {
		return err
	}
	if gateway.Spec.PeerRouting && len(gateway.Spec.Routes)+max(len(peerGrants)-1, 0) > 32 {
		return &gatewayPeerRouteCapacityError{vpcRoutes: len(gateway.Spec.Routes), connectors: len(peerGrants)}
	}
	grants := make([]interface{}, 0, len(peerGrants))
	for _, peerGrant := range peerGrants {
		grant := map[string]interface{}{"network": gateway.Spec.NetworkRef, "peer": peerGrant.peer, "client_address": peerGrant.clientAddress, "gateway_address": peerGrant.gatewayAddress, "routes": gateway.Spec.Routes, "interface_name": peerGrant.interfaceName, "mtu": 1280}
		if gateway.Spec.PeerRouting {
			grant["peer_routes"] = peerRoutes(peerGrants, peerGrant.peer)
		}
		grants = append(grants, grant)
	}
	grantJSON, err := json.Marshal(map[string]interface{}{"grants": grants})
	if err != nil {
		return err
	}
	gatewayYAML := "ipv6_addr: \"[::]:0\"\ndiscovery_mode: default\ntransport: masque\nip_config: /etc/connect/gateway/grants.json\n"
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: gatewayChildName(gateway.Name, "config"), Namespace: gateway.Namespace}}
	_, err = controllerutil.CreateOrUpdate(ctx, c, configMap, func() error {
		configMap.Data = map[string]string{"gateway.yaml": gatewayYAML, "grants.json": string(grantJSON)}
		return controllerutil.SetControllerReference(gateway, configMap, scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile gateway config ConfigMap: %w", err)
	}
	workload := &unstructured.Unstructured{}
	workload.SetGroupVersionKind(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"})
	workload.SetName(gatewayChildName(gateway.Name, "workload"))
	workload.SetNamespace(gateway.Namespace)
	desired := gatewayWorkloadSpec(gateway.Spec, configMap.Name, secretName)
	template := desired["template"].(map[string]interface{})
	template["metadata"] = map[string]interface{}{"annotations": map[string]interface{}{
		"connect.datumapis.com/config-hash": fmt.Sprintf("%x", sha256.Sum256([]byte(gatewayYAML+"\x00"+string(grantJSON)))),
	}}
	_, err = controllerutil.CreateOrUpdate(ctx, c, workload, func() error {
		if err := controllerutil.SetControllerReference(gateway, workload, scheme); err != nil {
			return err
		}
		workload.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "connect-controller", "connect.datumapis.com/gateway": gateway.Name})
		return unstructured.SetNestedMap(workload.Object, desired, "spec")
	})
	if err != nil {
		return fmt.Errorf("reconcile Compute gateway Workload: %w", err)
	}
	legacyWorkloadName := legacyGatewayWorkloadName(gateway.Name)
	if legacyWorkloadName != workload.GetName() {
		legacy := &unstructured.Unstructured{}
		legacy.SetGroupVersionKind(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"})
		legacy.SetName(legacyWorkloadName)
		legacy.SetNamespace(gateway.Namespace)
		if err := c.Get(ctx, types.NamespacedName{Name: legacyWorkloadName, Namespace: gateway.Namespace}, legacy); err == nil {
			if metav1.IsControlledBy(legacy, gateway) {
				if err := c.Delete(ctx, legacy); err != nil && !apierrors.IsNotFound(err) {
					return fmt.Errorf("remove legacy Compute gateway Workload: %w", err)
				}
			}
		} else if !apierrors.IsNotFound(err) {
			return fmt.Errorf("get legacy Compute gateway Workload: %w", err)
		}
	}
	gateway.Status.WorkloadRef = workload.GetName()
	return nil
}

func reconcileNetworkBinding(ctx context.Context, c client.Client, project string, binding *connectv1alpha1.ConnectNetworkBinding) error {
	before := binding.Status.DeepCopy()
	status, reason, message := metav1.ConditionFalse, "GatewayNotFound", "referenced ConnectGateway does not exist in this project"
	var gateway connectv1alpha1.ConnectGateway
	err := c.Get(ctx, types.NamespacedName{Name: binding.Spec.GatewayRef, Namespace: binding.Namespace}, &gateway)
	if err == nil {
		var connector connectv1alpha1.Connector
		err = c.Get(ctx, types.NamespacedName{Name: binding.Spec.ConnectorRef, Namespace: binding.Namespace}, &connector)
		if apierrors.IsNotFound(err) {
			reason, message = "ConnectorNotFound", "referenced Connector does not exist in this project"
		} else if err != nil {
			return err
		} else if !meta.IsStatusConditionTrue(connector.Status.Conditions, "Ready") {
			status, reason, message = metav1.ConditionFalse, "ConnectorNotReady", "referenced Connector is not online"
		} else if gateway.Status.EndpointID == "" {
			status, reason, message = metav1.ConditionUnknown, "GatewayProvisioning", "waiting for the gateway identity to be created"
		} else {
			clientAddress, peerAddress, _ := gatewayPeerAddresses(project, gateway.Spec.NetworkRef, strings.ToLower(connector.Spec.PublicKey), strings.ToLower(gateway.Status.EndpointID))
			binding.Status.EndpointID = gateway.Status.EndpointID
			binding.Status.AssignedAddress = clientAddress + "/128"
			binding.Status.PeerAddress = peerAddress + "/128"
			binding.Status.Routes = append([]string(nil), gateway.Spec.Routes...)
			capacityExceeded := false
			if gateway.Spec.PeerRouting {
				peerGrants, grantsErr := readyGatewayGrants(ctx, c, project, &gateway, gateway.Status.EndpointID)
				if grantsErr != nil {
					return grantsErr
				}
				connectorPeerRoutes := peerRoutes(peerGrants, strings.ToLower(connector.Spec.PublicKey))
				if len(binding.Status.Routes)+len(connectorPeerRoutes) > 32 {
					capacityExceeded = true
					binding.Status.Routes = nil
					status, reason, message = metav1.ConditionFalse, "PeerRouteCapacityExceeded", "VPC and peer routes would exceed the 32-route limit"
				} else {
					binding.Status.Routes = append(binding.Status.Routes, connectorPeerRoutes...)
				}
			}
			binding.Status.RelayURLs = append([]string(nil), gateway.Spec.RelayURLs...)
			if !capacityExceeded {
				workload := &unstructured.Unstructured{}
				workload.SetGroupVersionKind(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"})
				if gateway.Status.WorkloadRef == "" {
					status, reason, message = metav1.ConditionUnknown, "GatewayProvisioning", "waiting for the gateway Workload to be created"
				} else if err := c.Get(ctx, types.NamespacedName{Name: gateway.Status.WorkloadRef, Namespace: gateway.Namespace}, workload); err != nil {
					if !apierrors.IsNotFound(err) {
						return err
					}
					status, reason, message = metav1.ConditionUnknown, "GatewayProvisioning", "waiting for the gateway Workload to be created"
				} else if !gatewayWorkloadReady(workload) || !gatewayWorkloadConfigApplied(ctx, c, &gateway, workload) || !gatewayConfigIncludesConnector(ctx, c, &gateway, strings.ToLower(connector.Spec.PublicKey)) {
					status, reason, message = metav1.ConditionUnknown, "GatewayApplyingGrant", "waiting for the gateway Workload to apply this Connector grant and become available"
				} else {
					status, reason, message = metav1.ConditionTrue, "Approved", "gateway Workload is available with this Connector approved for its configured routes"
				}
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{Type: "Accepted", Status: status, Reason: reason, Message: message, ObservedGeneration: binding.Generation})
	binding.Status.ObservedGeneration = binding.Generation
	if reflect.DeepEqual(before, &binding.Status) {
		return nil
	}
	return c.Status().Update(ctx, binding)
}

type gatewayGrant struct {
	peer           string
	clientAddress  string
	gatewayAddress string
	interfaceName  string
}

type gatewayPeerRouteCapacityError struct {
	vpcRoutes  int
	connectors int
}

func (e *gatewayPeerRouteCapacityError) Error() string {
	return fmt.Sprintf("peer routing for %d Connectors plus %d VPC routes would advertise more than 32 routes per Connector; reduce routes or attached Connectors", e.connectors, e.vpcRoutes)
}

func readyGatewayGrants(ctx context.Context, c client.Client, project string, gateway *connectv1alpha1.ConnectGateway, endpointID string) ([]gatewayGrant, error) {
	bindings := &connectv1alpha1.ConnectNetworkBindingList{}
	if err := c.List(ctx, bindings, client.InNamespace(gateway.Namespace)); err != nil {
		return nil, err
	}
	byPeer := make(map[string]gatewayGrant, len(bindings.Items))
	for i := range bindings.Items {
		binding := &bindings.Items[i]
		if binding.Spec.GatewayRef != gateway.Name || binding.DeletionTimestamp != nil {
			continue
		}
		var connector connectv1alpha1.Connector
		if err := c.Get(ctx, types.NamespacedName{Name: binding.Spec.ConnectorRef, Namespace: binding.Namespace}, &connector); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		// Gateway grants represent durable authorization from the existence of
		// the Connector and its binding. Do not remove a grant just because the
		// Connector's liveness lease expires temporarily: that would change the
		// gateway Workload config and restart the gateway, interrupting every
		// other attached Connector. Binding readiness still checks the liveness
		// condition before allowing a client to join.
		if !meta.IsStatusConditionTrue(connector.Status.Conditions, "Accepted") {
			continue
		}
		peer := strings.ToLower(connector.Spec.PublicKey)
		clientAddress, gatewayAddress, interfaceName := gatewayPeerAddresses(project, gateway.Spec.NetworkRef, peer, strings.ToLower(endpointID))
		byPeer[peer] = gatewayGrant{peer: peer, clientAddress: clientAddress + "/128", gatewayAddress: gatewayAddress + "/128", interfaceName: interfaceName}
	}
	peers := make([]string, 0, len(byPeer))
	for peer := range byPeer {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	grants := make([]gatewayGrant, 0, len(peers))
	for _, peer := range peers {
		grants = append(grants, byPeer[peer])
	}
	return grants, nil
}

func peerRoutes(grants []gatewayGrant, localPeer string) []string {
	capacity := len(grants)
	if capacity > 0 {
		capacity--
	}
	routes := make([]string, 0, capacity)
	for _, grant := range grants {
		if grant.peer != localPeer {
			routes = append(routes, grant.clientAddress)
		}
	}
	return routes
}

func gatewayWorkloadReady(workload *unstructured.Unstructured) bool {
	available := false
	conditions, _, _ := unstructured.NestedSlice(workload.Object, "status", "conditions")
	for _, raw := range conditions {
		condition, ok := raw.(map[string]interface{})
		if ok && condition["type"] == "Available" && condition["status"] == "True" {
			available = true
		}
	}
	generation := workload.GetGeneration()
	observedGeneration, _, _ := unstructured.NestedInt64(workload.Object, "status", "observedGeneration")
	desiredReplicas, _, _ := unstructured.NestedInt64(workload.Object, "status", "desiredReplicas")
	readyReplicas, _, _ := unstructured.NestedInt64(workload.Object, "status", "readyReplicas")
	updatedReplicas, _, _ := unstructured.NestedInt64(workload.Object, "status", "updatedReplicas")
	return available && observedGeneration >= generation && desiredReplicas > 0 && readyReplicas >= desiredReplicas && updatedReplicas >= desiredReplicas
}

func gatewayWorkloadConfigApplied(ctx context.Context, c client.Client, gateway *connectv1alpha1.ConnectGateway, workload *unstructured.Unstructured) bool {
	config := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: gateway.Namespace}, config); err != nil {
		return false
	}
	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(config.Data["gateway.yaml"]+"\x00"+config.Data["grants.json"])))
	workloadHash, found, err := unstructured.NestedString(workload.Object, "spec", "template", "metadata", "annotations", "connect.datumapis.com/config-hash")
	return err == nil && found && workloadHash == expectedHash
}

func gatewayConfigIncludesConnector(ctx context.Context, c client.Client, gateway *connectv1alpha1.ConnectGateway, publicKey string) bool {
	config := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: gateway.Namespace}, config); err != nil {
		return false
	}
	var grants struct {
		Grants []struct {
			Peer string `json:"peer"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(config.Data["grants.json"]), &grants); err != nil {
		return false
	}
	for _, grant := range grants.Grants {
		if strings.EqualFold(grant.Peer, publicKey) {
			return true
		}
	}
	return false
}

func gatewayWorkloadSpec(spec connectv1alpha1.ConnectGatewaySpec, configName, secretName string) map[string]interface{} {
	instanceType := spec.InstanceType
	if instanceType == "" {
		instanceType = "datumcloud/d1-standard-2"
	}
	container := map[string]interface{}{"name": "connect-gateway", "image": spec.Image, "command": []interface{}{"/bin/sh", "-ec"}, "args": []interface{}{"mkdir -p /dev/net && (test -c /dev/net/tun || mknod /dev/net/tun c 10 200) && install -D -m 600 /etc/connect/key/key /run/connect-inputs/key && install -D -m 600 /etc/connect/gateway/gateway.yaml /run/connect-inputs/gateway.yaml && install -D -m 600 /etc/connect/gateway/grants.json /run/connect-inputs/grants.json && exec /usr/local/bin/iroh-gateway --config-file=/run/connect-inputs/gateway.yaml --key-file=/run/connect-inputs/key"}, "securityContext": map[string]interface{}{"capabilities": map[string]interface{}{"add": []interface{}{"NET_ADMIN", "MKNOD"}}}, "volumeAttachments": []interface{}{map[string]interface{}{"name": "connect-config", "mountPath": "/etc/connect/gateway"}, map[string]interface{}{"name": "connect-key", "mountPath": "/etc/connect/key"}}}
	container["args"] = []interface{}{"mkdir -p /dev/net && (test -c /dev/net/tun || mknod /dev/net/tun c 10 200) && install -D -m 600 /etc/connect/key/key /run/connect-inputs/key && install -D -m 600 /etc/connect/gateway/gateway.yaml /run/connect-inputs/gateway.yaml && install -D -m 600 /etc/connect/gateway/grants.json /run/connect-inputs/grants.json && exec /usr/local/bin/iroh-gateway --config-file=/run/connect-inputs/gateway.yaml --key-file=/run/connect-inputs/key --ip-config=/run/connect-inputs/grants.json --metrics-addr=127.0.0.1 --metrics-port=9090"}
	if len(spec.RelayURLs) > 0 {
		container["env"] = []interface{}{map[string]interface{}{"name": "IROH_GATEWAY_RELAY_URLS", "value": strings.Join(spec.RelayURLs, ",")}}
	}
	return map[string]interface{}{
		"placements": []interface{}{map[string]interface{}{"name": "gateway", "locationSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"topology.datum.net/city-code": spec.LocationRef}}, "scaleSettings": map[string]interface{}{"minReplicas": int64(1), "instanceManagementPolicy": "OrderedReady"}}},
		"template": map[string]interface{}{"spec": map[string]interface{}{
			"networkInterfaces": []interface{}{map[string]interface{}{"name": "eth0", "network": map[string]interface{}{"name": spec.NetworkRef}, "ipFamilies": []interface{}{"IPv6"}}},
			"runtime": map[string]interface{}{"class": "general-purpose", "resources": map[string]interface{}{"instanceType": instanceType}, "sandbox": map[string]interface{}{
				"sysctls":    []interface{}{map[string]interface{}{"name": "net.ipv6.conf.all.forwarding", "value": "1"}, map[string]interface{}{"name": "net.ipv6.conf.default.forwarding", "value": "1"}},
				"containers": []interface{}{container},
			}},
			"volumes": []interface{}{map[string]interface{}{"name": "connect-config", "configMap": map[string]interface{}{"name": configName}}, map[string]interface{}{"name": "connect-key", "secret": map[string]interface{}{"secretName": secretName, "defaultMode": int64(256)}}},
		}},
	}
}

func sortGatewayBindings(bindings []connectv1alpha1.ConnectNetworkBinding) {
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Name < bindings[j].Name })
}

func gatewayChildName(parent, suffix string) string {
	hash := sha256.Sum256([]byte(parent + "/" + suffix))
	if suffix == "workload" {
		return fmt.Sprintf("connect-gw-%x", hash[:4])
	}
	name := strings.Trim(strings.ToLower(parent), "-")
	if len(name) > 37 {
		name = name[:37]
	}
	return fmt.Sprintf("connect-%s-%s-%x", name, suffix, hash[:4])
}

func legacyGatewayWorkloadName(parent string) string {
	name := strings.Trim(strings.ToLower(parent), "-")
	if len(name) > 37 {
		name = name[:37]
	}
	hash := sha256.Sum256([]byte(parent + "/workload"))
	return fmt.Sprintf("connect-%s-workload-%x", name, hash[:4])
}

func gatewayPeerAddresses(project, network, clientKey, gatewayKey string) (string, string, string) {
	a, b := clientKey, gatewayKey
	if b < a {
		a, b = b, a
	}
	address := func(key string) string {
		digest := gatewayDigest(project, network, a, b, key)
		var address [16]byte
		copy(address[:], digest[:16])
		address[0] = 0xfd
		return netip.AddrFrom16(address).String()
	}
	// The gateway creates one TUN interface per peer grant. Include both peer
	// identities so multiple Connectors on the same gateway don't collide.
	label := gatewayDigest(project, network, a, b)
	return address(clientKey), address(gatewayKey), fmt.Sprintf("d%x", label[:7])
}

func gatewayDigest(parts ...string) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("datum-connect/peer-host/v1\x00"))
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		hash.Write(length[:])
		hash.Write([]byte(part))
	}
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

func schemeForGateway() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = connectv1alpha1.AddToScheme(s)
	return s
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
