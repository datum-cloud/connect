package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
)

type ConnectReconciler struct {
	mgr         mcmanager.Manager
	kind        string
	classClient client.Client
}

// +kubebuilder:rbac:groups=connect.datumapis.com,resources=connectorclasses;connectors;connectoradvertisements;connectgateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=connect.datumapis.com,resources=connectorclasses/status;connectors/status;connectoradvertisements/status;connectgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch

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
		{"connectoradvertisement", &connectv1alpha1.ConnectorAdvertisement{}},
		{"connectgateway", &connectv1alpha1.ConnectGateway{}},
	} {
		builder := mcbuilder.ControllerManagedBy(mgr).Named(item.name).For(item.obj,
			mcbuilder.WithEngageWithLocalCluster(false))
		if item.name == "connector" {
			builder = builder.Owns(&coordinationv1.Lease{})
		}
		if err := builder.Complete(&ConnectReconciler{mgr: mgr, kind: item.name, classClient: local.GetClient()}); err != nil {
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
		if err := reconcileConnector(ctx, c, r.classClient, &obj); err != nil {
			logger.Error(err, "reconcile Connector")
			return ctrl.Result{}, err
		}
		// Recheck expiry even if no Lease update arrives at the exact TTL edge.
		// Lease renewals also enqueue the owning Connector through Owns above.
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
		if err := reconcileGateway(ctx, c, &obj); err != nil {
			logger.Error(err, "reconcile ConnectGateway")
			return ctrl.Result{}, err
		}
		if condition := meta.FindStatusCondition(obj.Status.Conditions, "Ready"); condition != nil && (condition.Reason == "ConnectorNotFound" || condition.Reason == "ConnectorNotReady") {
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
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

func reconcileConnector(ctx context.Context, c, classClient client.Client, obj *connectv1alpha1.Connector) error {
	before := obj.Status.DeepCopy()
	accepted, acceptedReason, acceptedMessage := metav1.ConditionTrue, "Accepted", "Connector class and identity are valid"
	if _, err := hex.DecodeString(obj.Spec.PublicKey); err != nil || len(obj.Spec.PublicKey) != 64 {
		accepted, acceptedReason, acceptedMessage = metav1.ConditionFalse, "InvalidPublicKey", "publicKey must be a 32-byte hexadecimal iroh public key"
	} else if errs := validation.IsDNS1123Subdomain(obj.Spec.ClassRef); len(errs) > 0 {
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
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: "Accepted", Status: accepted, Reason: acceptedReason, Message: acceptedMessage, ObservedGeneration: obj.Generation})
	ready, readyReason, readyMessage := metav1.ConditionFalse, "NotReady", "waiting for a valid Connector configuration"
	if accepted == metav1.ConditionTrue {
		lease, err := ensureConnectorLease(ctx, c, obj)
		if err != nil {
			return err
		}
		obj.Status.LeaseRef = lease.Name
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
		return nil
	}
	return c.Status().Update(ctx, obj)
}

func ensureConnectorLease(ctx context.Context, c client.Client, connector *connectv1alpha1.Connector) (*coordinationv1.Lease, error) {
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: connector.Name, Namespace: connector.Namespace}}
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

func schemeForConnector() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = coordinationv1.AddToScheme(s)
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

func reconcileGateway(ctx context.Context, c client.Client, obj *connectv1alpha1.ConnectGateway) error {
	before := obj.Status.DeepCopy()
	status, reason, message := metav1.ConditionUnknown, "IntegrationPending", "gateway reconciliation requires NetworkBinding and Compute workload integration"
	if obj.Spec.ConnectorRef == "" || obj.Spec.NetworkRef == "" {
		status, reason, message = metav1.ConditionFalse, "InvalidReference", "connectorRef and networkRef are required"
	} else {
		var connector connectv1alpha1.Connector
		err := c.Get(ctx, types.NamespacedName{Name: obj.Spec.ConnectorRef}, &connector)
		if apierrors.IsNotFound(err) {
			status, reason, message = metav1.ConditionFalse, "ConnectorNotFound", "referenced Connector does not exist in this project"
		} else if err != nil {
			return err
		} else if !meta.IsStatusConditionTrue(connector.Status.Conditions, "Ready") {
			status, reason, message = metav1.ConditionFalse, "ConnectorNotReady", "referenced Connector is not ready"
		}
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: "Ready", Status: status, Reason: reason, Message: message, ObservedGeneration: obj.Generation})
	obj.Status.ObservedGeneration = obj.Generation
	if reflect.DeepEqual(before, &obj.Status) {
		return nil
	}
	return c.Status().Update(ctx, obj)
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
