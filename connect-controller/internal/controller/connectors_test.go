package controller

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func testClient(t *testing.T, objs ...runtime.Object) *fake.ClientBuilder {
	t.Helper()
	s := runtime.NewScheme()
	if err := connectv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := coordinationv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := iamv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := identityv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"}, &unstructured.Unstructured{})
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "WorkloadList"}, &unstructured.UnstructuredList{})
	return fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objs...).WithStatusSubresource(&connectv1alpha1.Connector{}, &connectv1alpha1.ConnectorClass{}, &connectv1alpha1.ConnectorAdvertisement{}, &connectv1alpha1.ConnectGateway{}, &connectv1alpha1.ConnectNetworkBinding{}, &iamv1alpha1.ServiceAccount{}, serviceAccountKeyObject())
}

func authenticationKey(t *testing.T, connector *connectv1alpha1.Connector, id, state string, privateKey *rsa.PrivateKey) connectv1alpha1.ConnectorAuthenticationKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(connectorEnrollmentStatement(connector, id, der))
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	return connectv1alpha1.ConnectorAuthenticationKey{
		ID: id, State: state,
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		Proof:     base64.RawURLEncoding.EncodeToString(signature),
	}
}

func serviceAccountKeyObject() *identityv1alpha1.ServiceAccountKey {
	object := &identityv1alpha1.ServiceAccountKey{}
	object.SetGroupVersionKind(identityv1alpha1.SchemeGroupVersion.WithKind("ServiceAccountKey"))
	return object
}

func TestReconcileConnectorChecksPlatformClass(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "laptop", UID: types.UID("laptop-uid")}, Spec: connectv1alpha1.ConnectorSpec{ClassRef: "masque", PublicKey: strings.Repeat("a", 64)}}
	legacyController := true
	legacyLease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
		Name: "laptop",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "networking.datumapis.com/v1alpha1",
			Kind:       "Connector",
			Name:       "laptop",
			UID:        types.UID("legacy-laptop-uid"),
			Controller: &legacyController,
		}},
	}}
	projectClient := testClient(t, connector, legacyLease).Build()
	classClient := testClient(t).Build()
	if err := reconcileConnector(ctx, projectClient, classClient, nil, ConnectorIdentityConfig{}, "consumer", connector, nil); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(connector.Status.Conditions, "Accepted").Reason; got != "ClassNotFound" {
		t.Fatalf("reason=%q, want ClassNotFound", got)
	}

	class := &connectv1alpha1.ConnectorClass{ObjectMeta: metav1.ObjectMeta{Name: "masque"}, Spec: connectv1alpha1.ConnectorClassSpec{Transports: []string{"masque-v1"}}}
	classClient = testClient(t, class).Build()
	if err := reconcileConnector(ctx, projectClient, classClient, nil, ConnectorIdentityConfig{}, "consumer", connector, nil); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(connector.Status.Conditions, "Accepted").Status; got != metav1.ConditionTrue {
		t.Fatalf("accepted=%q, want True", got)
	}
	if condition := meta.FindStatusCondition(connector.Status.Conditions, "AuthenticationReady"); condition == nil || condition.Status != metav1.ConditionUnknown || condition.Reason != "LegacyCredentials" {
		t.Fatalf("authentication condition=%#v, want explicit two-step enrollment pending state", condition)
	}
	if got := meta.FindStatusCondition(connector.Status.Conditions, "Ready").Reason; got != "AgentOffline" {
		t.Fatalf("ready reason=%q, want AgentOffline until the agent renews its Lease", got)
	}
	if got, want := connector.Status.LeaseRef, connectorLeaseName(connector.Name); got != want {
		t.Fatalf("leaseRef=%q, want Connect-specific Lease %q", got, want)
	}
	var lease coordinationv1.Lease
	if err := projectClient.Get(ctx, types.NamespacedName{Name: connectorLeaseName(connector.Name)}, &lease); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewMicroTime(time.Now())
	lease.Spec.RenewTime = &now
	if err := projectClient.Update(ctx, &lease); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, nil, ConnectorIdentityConfig{}, "consumer", connector, nil); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(connector.Status.Conditions, "Ready").Status; got != metav1.ConditionTrue {
		t.Fatalf("ready=%q after Lease renewal, want True", got)
	}
	var preservedLegacyLease coordinationv1.Lease
	if err := projectClient.Get(ctx, types.NamespacedName{Name: "laptop"}, &preservedLegacyLease); err != nil {
		t.Fatal(err)
	}
	if got := preservedLegacyLease.OwnerReferences[0].UID; got != types.UID("legacy-laptop-uid") {
		t.Fatalf("legacy Lease owner UID=%q, want it preserved", got)
	}
}

func TestConnectorAuthenticationUsesPlatformIdentityAndExactConsumerBinding(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "project", UID: types.UID("connector-uid"), Generation: 1},
		Spec:       connectv1alpha1.ConnectorSpec{ClassRef: "masque", PublicKey: strings.Repeat("a", 64)},
	}
	class := &connectv1alpha1.ConnectorClass{ObjectMeta: metav1.ObjectMeta{Name: "masque"}, Spec: connectv1alpha1.ConnectorClassSpec{Transports: []string{"masque-v1"}}}
	projectClient := testClient(t, connector).Build()
	classClient := testClient(t, class).Build()
	identityClient := testClient(t).Build()
	identityConfig := ConnectorIdentityConfig{Project: "platform-identities", KeyNamespace: "connector-keys", RoleName: "connector-agent", RoleNamespace: "milo-system"}

	// Bootstrap is necessarily two-step: the initial authorized create obtains
	// metadata.uid; only then can the client create a non-replayable proof.
	if err := reconcileConnector(ctx, projectClient, classClient, nil, identityConfig, "consumer-project", connector, nil); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(connector.Status.Conditions, "AuthenticationReady"); condition == nil || condition.Reason != "LegacyCredentials" {
		t.Fatalf("initial authentication condition=%#v", condition)
	}

	firstPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	first := authenticationKey(t, connector, "first", "Active", firstPrivate)
	enrollment := &connectv1alpha1.ConnectorEnrollment{ObjectMeta: metav1.ObjectMeta{Name: connector.Name, Namespace: connector.Namespace}, Spec: connectv1alpha1.ConnectorEnrollmentSpec{ConnectorRef: connectv1alpha1.ConnectorEnrollmentReference{Name: connector.Name, UID: string(connector.UID)}, Key: first}}
	if err := projectClient.Create(ctx, enrollment); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, identityClient, identityConfig, "consumer-project", connector, enrollment); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(connector.Status.Conditions, "AuthenticationReady"); condition == nil || condition.Reason != "IdentityProvisioning" {
		t.Fatalf("service-account provisioning condition=%#v", condition)
	}

	serviceAccount := &iamv1alpha1.ServiceAccount{}
	serviceAccountKey := types.NamespacedName{Name: connectorIdentityName(connector.UID)}
	if err := identityClient.Get(ctx, serviceAccountKey, serviceAccount); err != nil {
		t.Fatal(err)
	}
	if serviceAccount.Namespace != "" {
		t.Fatalf("Milo cluster-scoped ServiceAccount namespace=%q, want empty", serviceAccount.Namespace)
	}
	if errs := validation.IsValidLabelValue(serviceAccount.Labels[connectorUIDLabel]); len(errs) != 0 {
		t.Fatalf("Connector UID binding label is invalid: %v", errs)
	}
	serviceAccount.UID = types.UID("service-account-uid")
	serviceAccount.Status.Email = "connector@example.invalid"
	serviceAccount.Status.ClientID = "provider-client-id"
	meta.SetStatusCondition(&serviceAccount.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: "Provisioning"})
	if err := identityClient.Status().Update(ctx, serviceAccount); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, identityClient, identityConfig, "consumer-project", connector, enrollment); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(connector.Status.Conditions, "AuthenticationReady"); condition == nil || condition.Reason != "IdentityProvisioning" {
		t.Fatalf("service-account readiness condition=%#v, service account=%#v", condition, serviceAccount)
	}
	firstResourceKey := types.NamespacedName{Name: connectorAuthenticationKeyName(connector.UID, "first"), Namespace: identityConfig.KeyNamespace}
	if err := identityClient.Get(ctx, firstResourceKey, serviceAccountKeyObject()); !apierrors.IsNotFound(err) {
		t.Fatalf("ServiceAccountKey created before ServiceAccount Ready=True: %v", err)
	}
	if connector.Status.Authentication.PrincipalRef.ClientID != "" {
		t.Fatalf("client ID was derived instead of waiting for provider status: %q", connector.Status.Authentication.PrincipalRef.ClientID)
	}
	if err := identityClient.Get(ctx, serviceAccountKey, serviceAccount); err != nil {
		t.Fatal(err)
	}
	serviceAccount.Status.ClientID = ""
	meta.SetStatusCondition(&serviceAccount.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"})
	if err := identityClient.Status().Update(ctx, serviceAccount); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, identityClient, identityConfig, "consumer-project", connector, enrollment); err != nil {
		t.Fatal(err)
	}
	if err := identityClient.Get(ctx, firstResourceKey, serviceAccountKeyObject()); !apierrors.IsNotFound(err) {
		t.Fatalf("ServiceAccountKey created before ServiceAccount client ID was published: %v", err)
	}
	if err := identityClient.Get(ctx, serviceAccountKey, serviceAccount); err != nil {
		t.Fatal(err)
	}
	serviceAccount.Status.ClientID = "provider-client-id"
	if err := identityClient.Status().Update(ctx, serviceAccount); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, identityClient, identityConfig, "consumer-project", connector, enrollment); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(connector.Status.Conditions, "AuthenticationReady"); condition == nil || condition.Reason != "IdentityProvisioning" {
		t.Fatalf("key provisioning condition=%#v, service account=%#v", condition, serviceAccount)
	}
	firstResource := serviceAccountKeyObject()
	if err := identityClient.Get(ctx, firstResourceKey, firstResource); err != nil {
		t.Fatal(err)
	}
	if len(firstResource.OwnerReferences) != 0 {
		t.Fatalf("cross-project ServiceAccountKey must not carry an invalid owner reference: %v", firstResource.OwnerReferences)
	}
	if firstResource.Spec.PublicKey != first.PublicKey || firstResource.Spec.ServiceAccountUserName != serviceAccount.Status.Email {
		t.Fatalf("registered key does not preserve the client public key and service-account client ID: %#v", firstResource.Spec)
	}
	firstResource.Status.AuthProviderKeyID = "provider-first"
	firstResource.SetGroupVersionKind(identityv1alpha1.SchemeGroupVersion.WithKind("ServiceAccountKey"))
	if err := identityClient.Status().Update(ctx, firstResource); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, identityClient, identityConfig, "consumer-project", connector, enrollment); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(connector.Status.Conditions, "AuthenticationReady"); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("authentication condition=%#v, want ready", condition)
	}
	if connector.Status.Authentication == nil || connector.Status.Authentication.ConnectorUID != string(connector.UID) || connector.Status.Authentication.PrincipalRef.ClientID != serviceAccount.Status.ClientID || connector.Status.Authentication.PrincipalRef.ClientEmail != serviceAccount.Status.Email || connector.Status.Authentication.PrincipalRef.Project != identityConfig.Project {
		t.Fatalf("authentication status is not bound to the immutable Connector UID: %#v", connector.Status.Authentication)
	}
	var binding iamv1alpha1.PolicyBinding
	if err := projectClient.Get(ctx, types.NamespacedName{Name: connectorIdentityName(connector.UID), Namespace: connector.Namespace}, &binding); err != nil {
		t.Fatal(err)
	}
	ref := binding.Spec.ResourceSelector.ResourceRef
	if ref == nil || ref.UID != string(connector.UID) || ref.Name != connector.Name || len(binding.Spec.Subjects) != 1 || binding.Spec.Subjects[0].UID != string(serviceAccount.UID) {
		t.Fatalf("policy binding is not exact-resource and UID scoped: %#v", binding.Spec)
	}
	var leaseBinding iamv1alpha1.PolicyBinding
	if err := projectClient.Get(ctx, types.NamespacedName{Name: connectorIdentityName(connector.UID) + "-lease", Namespace: connector.Namespace}, &leaseBinding); err != nil {
		t.Fatal(err)
	}
	if leaseRef := leaseBinding.Spec.ResourceSelector.ResourceRef; leaseRef == nil || leaseRef.Kind != "Lease" || leaseRef.Name != connectorLeaseName(connector.Name) {
		t.Fatalf("Lease policy binding is not exact-resource scoped: %#v", leaseBinding.Spec)
	}
	if serviceAccount.Annotations[connectorProjectAnnotation] != "consumer-project" || firstResource.Annotations[connectorProjectAnnotation] != "consumer-project" {
		t.Fatal("platform identity resources do not record their consumer project")
	}

	if err := validateConnectorAuthentication(connector, enrollment); err != nil {
		t.Fatalf("protected enrollment failed validation: %v", err)
	}
	if err := projectClient.Delete(ctx, enrollment); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, identityClient, identityConfig, "consumer-project", connector, nil); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(connector.Status.Conditions, "AuthenticationReady"); condition == nil || condition.Reason != "EnrollmentMissing" || condition.Status != metav1.ConditionFalse {
		t.Fatalf("missing enrollment condition=%#v, want revoked", condition)
	}
	if connector.Status.Authentication != nil {
		t.Fatalf("revoked authentication provider identifiers remain in status: %#v", connector.Status.Authentication)
	}
	if !controllerutil.ContainsFinalizer(connector, connectorIdentityFinalizer) {
		t.Fatal("missing enrollment removed the Connector finalizer; recovery state must be retained")
	}
	if err := identityClient.Get(ctx, serviceAccountKey, &iamv1alpha1.ServiceAccount{}); !apierrors.IsNotFound(err) {
		t.Fatalf("platform ServiceAccount remains after enrollment revocation: %v", err)
	}
	if err := identityClient.Get(ctx, firstResourceKey, serviceAccountKeyObject()); !apierrors.IsNotFound(err) {
		t.Fatalf("platform ServiceAccountKey remains after enrollment revocation: %v", err)
	}
	if err := projectClient.Get(ctx, types.NamespacedName{Name: binding.Name, Namespace: binding.Namespace}, &iamv1alpha1.PolicyBinding{}); !apierrors.IsNotFound(err) {
		t.Fatalf("consumer PolicyBinding remains after enrollment revocation: %v", err)
	}
	if err := projectClient.Get(ctx, types.NamespacedName{Name: leaseBinding.Name, Namespace: leaseBinding.Namespace}, &iamv1alpha1.PolicyBinding{}); !apierrors.IsNotFound(err) {
		t.Fatalf("consumer Lease PolicyBinding remains after enrollment revocation: %v", err)
	}

	if err := projectClient.Delete(ctx, connector); err != nil {
		t.Fatal(err)
	}
	if err := projectClient.Get(ctx, types.NamespacedName{Name: connector.Name, Namespace: connector.Namespace}, connector); err != nil {
		t.Fatal(err)
	}
	if err := reconcileConnector(ctx, projectClient, classClient, identityClient, identityConfig, "consumer-project", connector, nil); err != nil {
		t.Fatal(err)
	}
	if err := identityClient.Get(ctx, serviceAccountKey, &iamv1alpha1.ServiceAccount{}); !apierrors.IsNotFound(err) {
		t.Fatalf("platform ServiceAccount still exists after finalization: %v", err)
	}
	if err := identityClient.Get(ctx, firstResourceKey, serviceAccountKeyObject()); !apierrors.IsNotFound(err) {
		t.Fatalf("platform ServiceAccountKey still exists after finalization: %v", err)
	}
	if err := projectClient.Get(ctx, types.NamespacedName{Name: binding.Name, Namespace: binding.Namespace}, &iamv1alpha1.PolicyBinding{}); !apierrors.IsNotFound(err) {
		t.Fatalf("consumer PolicyBinding still exists after finalization: %v", err)
	}
	if err := projectClient.Get(ctx, types.NamespacedName{Name: leaseBinding.Name, Namespace: leaseBinding.Namespace}, &iamv1alpha1.PolicyBinding{}); !apierrors.IsNotFound(err) {
		t.Fatalf("consumer Lease PolicyBinding still exists after finalization: %v", err)
	}
	if err := projectClient.Get(ctx, types.NamespacedName{Name: enrollment.Name, Namespace: enrollment.Namespace}, &connectv1alpha1.ConnectorEnrollment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("protected enrollment still exists after finalization: %v", err)
	}
}

func TestConnectorFinalizerWaitsForConfirmedCredentialDeletion(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	connector := &connectv1alpha1.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "laptop",
			Namespace:         "project",
			UID:               types.UID("connector-uid"),
			Finalizers:        []string{connectorIdentityFinalizer},
			DeletionTimestamp: &now,
		},
	}
	name := connectorIdentityName(connector.UID)
	uidLabel := map[string]string{connectorUIDLabel: connectorUIDHash(connector.UID)}
	enrollment := &connectv1alpha1.ConnectorEnrollment{ObjectMeta: metav1.ObjectMeta{Name: connector.Name, Namespace: connector.Namespace}}
	binding := &iamv1alpha1.PolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: connector.Namespace}}
	leaseBinding := &iamv1alpha1.PolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: name + "-lease", Namespace: connector.Namespace}}
	serviceAccount := &iamv1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: iamv1alpha1.ServiceAccountSpec{State: "Active"}}
	serviceAccountKey := serviceAccountKeyObject()
	serviceAccountKey.Name = connectorAuthenticationKeyName(connector.UID, "current")
	serviceAccountKey.Namespace = "connector-keys"
	serviceAccountKey.Labels = uidLabel

	deletionsPersist := true
	deleteInterceptor := interceptor.Funcs{Delete: func(ctx context.Context, underlying client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		if deletionsPersist {
			return nil
		}
		return underlying.Delete(ctx, obj, opts...)
	}}
	projectClient := testClient(t, connector, enrollment, binding, leaseBinding).WithInterceptorFuncs(deleteInterceptor).Build()
	identityClient := testClient(t, serviceAccount, serviceAccountKey).WithInterceptorFuncs(deleteInterceptor).Build()
	config := ConnectorIdentityConfig{Project: "platform-identities", KeyNamespace: "connector-keys"}

	if err := reconcileConnector(ctx, projectClient, nil, identityClient, config, "consumer-project", connector, enrollment); err != nil {
		t.Fatal(err)
	}
	if !controllerutil.ContainsFinalizer(connector, connectorIdentityFinalizer) {
		t.Fatal("finalizer was removed while credential deletion was still pending")
	}
	var deactivated iamv1alpha1.ServiceAccount
	if err := identityClient.Get(ctx, types.NamespacedName{Name: name}, &deactivated); err != nil {
		t.Fatal(err)
	}
	if deactivated.Spec.State != "Inactive" {
		t.Fatalf("service account state=%q, want Inactive while deletion is pending", deactivated.Spec.State)
	}

	deletionsPersist = false
	if err := reconcileConnector(ctx, projectClient, nil, identityClient, config, "consumer-project", connector, enrollment); err != nil {
		t.Fatal(err)
	}
	if controllerutil.ContainsFinalizer(connector, connectorIdentityFinalizer) {
		t.Fatal("finalizer remains after all credential resources were confirmed absent")
	}
}

func TestConnectorAuthenticationProofCannotBeCopiedAcrossUIDs(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	first := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{UID: types.UID("first-uid")}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("a", 64)}}
	key := authenticationKey(t, first, "current", "Active", privateKey)
	enrollment := &connectv1alpha1.ConnectorEnrollment{Spec: connectv1alpha1.ConnectorEnrollmentSpec{ConnectorRef: connectv1alpha1.ConnectorEnrollmentReference{Name: first.Name, UID: string(first.UID)}, Key: key}}
	if err := validateConnectorAuthentication(first, enrollment); err != nil {
		t.Fatalf("source proof did not verify: %v", err)
	}
	second := first.DeepCopy()
	second.UID = types.UID("second-uid")
	secondEnrollment := enrollment.DeepCopy()
	secondEnrollment.Spec.ConnectorRef.UID = string(second.UID)
	if err := validateConnectorAuthentication(second, secondEnrollment); err == nil || !strings.Contains(err.Error(), "proof of possession is invalid") {
		t.Fatalf("copied proof error=%v, want UID-bound proof rejection", err)
	}
}

func TestReconcileGatewayCreatesComputeWorkloadAndApprovesConnectorBinding(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("a", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	secondConnector := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "phone", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("b", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "vpc-gateway", Namespace: "project", UID: types.UID("gateway-uid")}, Spec: connectv1alpha1.ConnectGatewaySpec{NetworkRef: "private-net", LocationRef: "DFW", Routes: []string{"fd20:0:27::/48"}, Image: "ghcr.io/datum-cloud/iroh-gateway:connect-ip", PeerRouting: true}}
	c := testClient(t, connector, secondConnector, gateway).Build()
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
	if gateway.Status.EndpointID == "" || gateway.Status.WorkloadRef == "" {
		t.Fatalf("gateway status missing endpoint or workload ref: %#v", gateway.Status)
	}
	workload := &unstructured.Unstructured{}
	workload.SetGroupVersionKind(schema.GroupVersionKind{Group: "compute.datumapis.com", Version: "v1alpha", Kind: "Workload"})
	if err := c.Get(ctx, types.NamespacedName{Name: gateway.Status.WorkloadRef, Namespace: "project"}, workload); err != nil {
		t.Fatal(err)
	}
	deploymentLabel := workload.GetName() + "-gateway-us-central-1"
	if len(deploymentLabel) > 63 {
		t.Fatalf("generated WorkloadDeployment name %q exceeds Kubernetes label limit", deploymentLabel)
	}
	initialConfigHash, found, err := unstructured.NestedString(workload.Object, "spec", "template", "metadata", "annotations", "connect.datumapis.com/config-hash")
	if err != nil || !found || initialConfigHash == "" {
		t.Fatalf("initial config hash=%q found=%t err=%v", initialConfigHash, found, err)
	}
	placements, found, err := unstructured.NestedSlice(workload.Object, "spec", "placements")
	if err != nil || !found || len(placements) != 1 {
		t.Fatalf("placements=%v found=%t err=%v, want one", placements, found, err)
	}
	placement, ok := placements[0].(map[string]interface{})
	if !ok {
		t.Fatalf("placement=%T, want map", placements[0])
	}
	selector, ok := placement["locationSelector"].(map[string]interface{})
	if !ok || selector["matchLabels"].(map[string]interface{})["topology.datum.net/city-code"] != "DFW" {
		t.Fatalf("locationSelector=%v, want DFW city-code selector", placement["locationSelector"])
	}
	scaleSettings, ok := placement["scaleSettings"].(map[string]interface{})
	if !ok || scaleSettings["instanceManagementPolicy"] != "OrderedReady" {
		t.Fatalf("scaleSettings=%v, want explicitly declared OrderedReady policy", placement["scaleSettings"])
	}
	if scale, ok := placement["scaleSettings"].(map[string]interface{}); !ok || scale["minReplicas"] != int64(1) || scale["maxReplicas"] != nil {
		t.Fatalf("scaleSettings=%v, want minReplicas=1 without maxReplicas", placement["scaleSettings"])
	}
	instanceType, found, err := unstructured.NestedString(workload.Object, "spec", "template", "spec", "runtime", "resources", "instanceType")
	if err != nil || !found || instanceType != "datumcloud/d1-standard-2" {
		t.Fatalf("instanceType=%q found=%t err=%v, want datumcloud/d1-standard-2", instanceType, found, err)
	}
	interfaces, _, _ := unstructured.NestedSlice(workload.Object, "spec", "template", "spec", "networkInterfaces")
	if len(interfaces) != 1 {
		t.Fatalf("network interfaces=%v, want one VPC interface", interfaces)
	}
	attachments, _, _ := unstructured.NestedSlice(workload.Object, "spec", "template", "spec", "runtime", "sandbox", "containers")
	if len(attachments) != 1 {
		t.Fatalf("gateway containers=%v, want one", attachments)
	}
	container, ok := attachments[0].(map[string]interface{})
	if !ok {
		t.Fatalf("gateway container=%T, want map", attachments[0])
	}
	command, _, _ := unstructured.NestedStringSlice(container, "command")
	if len(command) != 2 || command[0] != "/bin/sh" {
		t.Fatalf("gateway command=%v, want TUN setup wrapper", command)
	}
	args, _, _ := unstructured.NestedStringSlice(container, "args")
	if len(args) != 1 || !strings.Contains(args[0], "mknod /dev/net/tun c 10 200") || !strings.Contains(args[0], "install -D -m 600 /etc/connect/key/key /run/connect-inputs/key") || !strings.Contains(args[0], "install -D -m 600 /etc/connect/gateway/grants.json /run/connect-inputs/grants.json") || !strings.Contains(args[0], "--config-file=/run/connect-inputs/gateway.yaml --key-file=/run/connect-inputs/key") {
		t.Fatalf("gateway args=%v, want TUN setup and safe staging of projected Secret/ConfigMap files", args)
	}
	if !strings.Contains(args[0], "--ip-config=/run/connect-inputs/grants.json") {
		t.Fatalf("gateway args=%v, want the strict IP grants loader to read the regular-file copy", args)
	}
	if !strings.Contains(args[0], "--metrics-addr=127.0.0.1 --metrics-port=9090") {
		t.Fatalf("gateway metrics must be available only on loopback: %s", args[0])
	}
	securityContext, ok := container["securityContext"].(map[string]interface{})
	if !ok {
		t.Fatalf("gateway securityContext=%T, want map", container["securityContext"])
	}
	capabilities, ok := securityContext["capabilities"].(map[string]interface{})
	if !ok {
		t.Fatalf("gateway capabilities=%T, want map", securityContext["capabilities"])
	}
	added, ok := capabilities["add"].([]interface{})
	if !ok || len(added) != 2 || added[0] != "NET_ADMIN" || added[1] != "MKNOD" {
		t.Fatalf("gateway capabilities=%v, want NET_ADMIN and MKNOD", capabilities["add"])
	}

	binding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "laptop-vpc", Namespace: "project", Generation: 1}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: connector.Name}}
	secondBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "phone-vpc", Namespace: "project", Generation: 1}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: secondConnector.Name}}
	// Create bindings in reverse peer-key order to ensure the rendered grants
	// are deterministic rather than dependent on API list order.
	for _, item := range []*connectv1alpha1.ConnectNetworkBinding{secondBinding, binding} {
		if err := c.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		if err := reconcileNetworkBinding(ctx, c, "project-id", item); err != nil {
			t.Fatal(err)
		}
		if condition := meta.FindStatusCondition(item.Status.Conditions, "Accepted"); condition == nil || condition.Status != metav1.ConditionUnknown || condition.Reason != "GatewayApplyingGrant" || item.Status.AssignedAddress == "" || item.Status.PeerAddress == "" {
			t.Fatalf("binding should wait for the grant rollout and have addresses: %#v", item.Status)
		}
	}
	if binding.Status.AssignedAddress == secondBinding.Status.AssignedAddress || binding.Status.PeerAddress == secondBinding.Status.PeerAddress {
		t.Fatalf("distinct Connectors received overlapping attachment addresses: first=%#v second=%#v", binding.Status, secondBinding.Status)
	}
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: gateway.Status.WorkloadRef, Namespace: "project"}, workload); err != nil {
		t.Fatal(err)
	}
	updatedConfigHash, found, err := unstructured.NestedString(workload.Object, "spec", "template", "metadata", "annotations", "connect.datumapis.com/config-hash")
	if err != nil || !found || updatedConfigHash == initialConfigHash {
		t.Fatalf("updated config hash=%q initial=%q found=%t err=%v; expected grant changes to roll the Workload", updatedConfigHash, initialConfigHash, found, err)
	}
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: "project"}, configMap); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Grants []map[string]interface{} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(configMap.Data["grants.json"]), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Grants) != 2 {
		t.Fatalf("grants=%v, want both approved Connector grants", config.Grants)
	}
	if config.Grants[0]["peer"] != connector.Spec.PublicKey || config.Grants[1]["peer"] != secondConnector.Spec.PublicKey {
		t.Fatalf("grants are not sorted by peer identity: %v", config.Grants)
	}
	firstPeerRoutes, ok := config.Grants[0]["peer_routes"].([]interface{})
	if !ok || len(firstPeerRoutes) != 1 || firstPeerRoutes[0] != config.Grants[1]["client_address"] {
		t.Fatalf("first grant peer_routes=%v, want second Connector address %v", config.Grants[0]["peer_routes"], config.Grants[1]["client_address"])
	}
	secondPeerRoutes, ok := config.Grants[1]["peer_routes"].([]interface{})
	if !ok || len(secondPeerRoutes) != 1 || secondPeerRoutes[0] != config.Grants[0]["client_address"] {
		t.Fatalf("second grant peer_routes=%v, want first Connector address %v", config.Grants[1]["peer_routes"], config.Grants[0]["client_address"])
	}
	grantInterfaces := map[string]bool{}
	addresses := map[string]bool{}
	for _, grant := range config.Grants {
		peer, _ := grant["peer"].(string)
		interfaceName, _ := grant["interface_name"].(string)
		clientAddress, _ := grant["client_address"].(string)
		gatewayAddress, _ := grant["gateway_address"].(string)
		if len(interfaceName) == 0 || len(interfaceName) > 15 || grantInterfaces[interfaceName] {
			t.Fatalf("grant for %q has invalid or duplicate interface %q: %v", peer, interfaceName, config.Grants)
		}
		grantInterfaces[interfaceName] = true
		for _, address := range []string{clientAddress, gatewayAddress} {
			if address == "" || addresses[address] {
				t.Fatalf("grant for %q has empty or duplicate address %q: %v", peer, address, config.Grants)
			}
			addresses[address] = true
		}
	}
	originalGrantJSON := configMap.Data["grants.json"]
	duplicateBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "laptop-vpc-alias", Namespace: "project", Generation: 1}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: connector.Name}}
	if err := c.Create(ctx, duplicateBinding); err != nil {
		t.Fatal(err)
	}
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: "project"}, configMap); err != nil {
		t.Fatal(err)
	}
	if configMap.Data["grants.json"] != originalGrantJSON {
		t.Fatalf("duplicate binding changed the canonical gateway grants: before=%s after=%s", originalGrantJSON, configMap.Data["grants.json"])
	}
	if err := unstructured.SetNestedSlice(workload.Object, []interface{}{map[string]interface{}{"type": "Available", "status": "True"}}, "status", "conditions"); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]interface{}{
		"observedGeneration": workload.GetGeneration(),
		"desiredReplicas":    int64(1),
		"readyReplicas":      int64(1),
		"updatedReplicas":    int64(1),
	} {
		if err := unstructured.SetNestedField(workload.Object, value, "status", path); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Update(ctx, workload); err != nil {
		t.Fatal(err)
	}
	for _, item := range []*connectv1alpha1.ConnectNetworkBinding{binding, secondBinding} {
		if err := reconcileNetworkBinding(ctx, c, "project-id", item); err != nil {
			t.Fatal(err)
		}
		if !meta.IsStatusConditionTrue(item.Status.Conditions, "Accepted") {
			t.Fatalf("binding should be accepted only after the gateway applies its grant: %#v", item.Status.Conditions)
		}
	}
	if got, want := binding.Status.Routes, []string{"fd20:0:27::/48", secondBinding.Status.AssignedAddress}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first binding routes=%v, want VPC and second Connector routes %v", got, want)
	}
	if got, want := secondBinding.Status.Routes, []string{"fd20:0:27::/48", binding.Status.AssignedAddress}; !reflect.DeepEqual(got, want) {
		t.Fatalf("second binding routes=%v, want VPC and first Connector routes %v", got, want)
	}
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(gateway.Status.Conditions, "Ready") {
		t.Fatalf("gateway should be ready after Compute Workload Available: %#v", gateway.Status.Conditions)
	}
}

func TestGatewayGrantInterfaceDerivationIsPerPeerAndSymmetric(t *testing.T) {
	gateway := strings.Repeat("f", 64)
	first := strings.Repeat("1", 64)
	second := strings.Repeat("2", 64)
	_, _, firstInterface := gatewayPeerAddresses("project", "vpc", first, gateway)
	_, _, reverseFirstInterface := gatewayPeerAddresses("project", "vpc", gateway, first)
	_, _, secondInterface := gatewayPeerAddresses("project", "vpc", second, gateway)
	if firstInterface != reverseFirstInterface {
		t.Fatalf("interface derivation is not symmetric: %q != %q", firstInterface, reverseFirstInterface)
	}
	if firstInterface == secondInterface {
		t.Fatalf("distinct peers share interface %q", firstInterface)
	}
	if len(firstInterface) > 15 || len(secondInterface) > 15 {
		t.Fatalf("interface names exceed Linux IFNAMSIZ: %q %q", firstInterface, secondInterface)
	}
}

func TestGatewayGrantPersistsWhenConnectorIsTemporarilyOffline(t *testing.T) {
	ctx := context.Background()
	connector := &connectv1alpha1.Connector{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop", Namespace: "project"},
		Spec:       connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("a", 64)},
		Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{
			{Type: "Accepted", Status: metav1.ConditionTrue},
			{Type: "Ready", Status: metav1.ConditionFalse, Reason: "AgentOffline"},
		}},
	}
	gateway := &connectv1alpha1.ConnectGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-gateway", Namespace: "project", UID: types.UID("gateway-uid")},
		Spec:       connectv1alpha1.ConnectGatewaySpec{NetworkRef: "private-net", LocationRef: "DFW", Routes: []string{"fd20:0:27::/48"}, Image: "ghcr.io/datum-cloud/iroh-gateway:connect-ip"},
	}
	binding := &connectv1alpha1.ConnectNetworkBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop-vpc", Namespace: "project"},
		Spec:       connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: connector.Name},
	}
	c := testClient(t, connector, gateway, binding).Build()
	if err := reconcileGatewayResources(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: gateway.Namespace}, configMap); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Grants []struct {
			Peer string `json:"peer"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(configMap.Data["grants.json"]), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Grants) != 1 || config.Grants[0].Peer != connector.Spec.PublicKey {
		t.Fatalf("gateway grants=%v, want offline but authorized Connector %q to retain its grant", config.Grants, connector.Spec.PublicKey)
	}
	if !meta.IsStatusConditionTrue(connector.Status.Conditions, "Accepted") || meta.IsStatusConditionTrue(connector.Status.Conditions, "Ready") {
		t.Fatalf("test Connector conditions=%v, want Accepted=True and Ready=False", connector.Status.Conditions)
	}
	if err := reconcileNetworkBinding(ctx, c, "project-id", binding); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(binding.Status.Conditions, "Accepted")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "ConnectorNotReady" {
		t.Fatalf("binding condition=%#v, want ConnectorNotReady while the Connector is offline", condition)
	}
}

func TestPeerRoutingIsDisabledByDefault(t *testing.T) {
	ctx := context.Background()
	first := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("1", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	second := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("2", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "project", UID: types.UID("gateway-uid")}, Spec: connectv1alpha1.ConnectGatewaySpec{NetworkRef: "private-net", LocationRef: "DFW", Routes: []string{"fd20::/48"}, Image: "gateway:dev"}}
	firstBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "first-vpc", Namespace: "project"}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: first.Name}}
	secondBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "second-vpc", Namespace: "project"}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: second.Name}}
	c := testClient(t, first, second, gateway, firstBinding, secondBinding).Build()
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: gatewayChildName(gateway.Name, "config"), Namespace: gateway.Namespace}, configMap); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Grants []map[string]interface{} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(configMap.Data["grants.json"]), &config); err != nil {
		t.Fatal(err)
	}
	for _, grant := range config.Grants {
		if _, found := grant["peer_routes"]; found {
			t.Fatalf("peer_routes must be omitted unless explicitly enabled: %v", grant)
		}
	}
	if err := reconcileNetworkBinding(ctx, c, "project-id", firstBinding); err != nil {
		t.Fatal(err)
	}
	if got, want := firstBinding.Status.Routes, gateway.Spec.Routes; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes=%v, want only VPC routes %v", got, want)
	}
}

func TestGatewayReportsPeerRouteCapacityExceeded(t *testing.T) {
	ctx := context.Background()
	routes := make([]string, 32)
	for index := range routes {
		routes[index] = fmt.Sprintf("fd20::%x/128", index+1)
	}
	first := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("1", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	second := &connectv1alpha1.Connector{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "project"}, Spec: connectv1alpha1.ConnectorSpec{PublicKey: strings.Repeat("2", 64)}, Status: connectv1alpha1.ConnectorStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}, {Type: "Ready", Status: metav1.ConditionTrue}}}}
	gateway := &connectv1alpha1.ConnectGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "project", UID: types.UID("gateway-uid")}, Spec: connectv1alpha1.ConnectGatewaySpec{NetworkRef: "private-net", LocationRef: "DFW", Routes: routes, Image: "gateway:dev", PeerRouting: true}}
	firstBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "first-vpc", Namespace: "project"}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: first.Name}}
	secondBinding := &connectv1alpha1.ConnectNetworkBinding{ObjectMeta: metav1.ObjectMeta{Name: "second-vpc", Namespace: "project"}, Spec: connectv1alpha1.ConnectNetworkBindingSpec{GatewayRef: gateway.Name, ConnectorRef: second.Name}}
	c := testClient(t, first, second, gateway, firstBinding, secondBinding).Build()
	if err := reconcileGateway(ctx, c, "project-id", gateway); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(gateway.Status.Conditions, "Ready")
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "PeerRouteCapacityExceeded" {
		t.Fatalf("gateway condition=%#v, want PeerRouteCapacityExceeded", condition)
	}
	if err := reconcileNetworkBinding(ctx, c, "project-id", firstBinding); err != nil {
		t.Fatal(err)
	}
	bindingCondition := meta.FindStatusCondition(firstBinding.Status.Conditions, "Accepted")
	if bindingCondition == nil || bindingCondition.Status != metav1.ConditionFalse || bindingCondition.Reason != "PeerRouteCapacityExceeded" || firstBinding.Status.Routes != nil {
		t.Fatalf("binding status=%#v, want route-capacity rejection without advertised routes", firstBinding.Status)
	}
}

func TestGatewayPeerAddressDerivationIsSymmetric(t *testing.T) {
	client := strings.Repeat("1", 64)
	gateway := strings.Repeat("2", 64)
	clientAddress, gatewayAddress, interfaceName := gatewayPeerAddresses("project", "vpc", client, gateway)
	reverseClientAddress, reverseGatewayAddress, reverseInterfaceName := gatewayPeerAddresses("project", "vpc", gateway, client)
	if clientAddress != reverseGatewayAddress || gatewayAddress != reverseClientAddress {
		t.Fatalf("addresses are not symmetric: (%s, %s) vs (%s, %s)", clientAddress, gatewayAddress, reverseClientAddress, reverseGatewayAddress)
	}
	if interfaceName != reverseInterfaceName {
		t.Fatalf("interface name is not symmetric: %q vs %q", interfaceName, reverseInterfaceName)
	}
	if len(interfaceName) > 15 {
		t.Fatalf("interface name %q exceeds Linux's 15-character limit", interfaceName)
	}
	_, _, secondInterfaceName := gatewayPeerAddresses("project", "vpc", strings.Repeat("3", 64), gateway)
	if interfaceName == secondInterfaceName {
		t.Fatalf("two Connector grants on one gateway share interface name %q", interfaceName)
	}
}

func TestSortGatewayBindingsMakesGrantOrderDeterministic(t *testing.T) {
	bindings := []connectv1alpha1.ConnectNetworkBinding{
		{ObjectMeta: metav1.ObjectMeta{Name: "connector-z"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "connector-a"}},
	}
	sortGatewayBindings(bindings)
	if bindings[0].Name != "connector-a" || bindings[1].Name != "connector-z" {
		t.Fatalf("binding order = [%s, %s], want stable alphabetical order", bindings[0].Name, bindings[1].Name)
	}
}

func TestGatewayRejectsDefaultRoute(t *testing.T) {
	spec := connectv1alpha1.ConnectGatewaySpec{NetworkRef: "vpc", LocationRef: "DFW", Image: "gateway:dev", Routes: []string{"::/0"}}
	if err := validateGatewaySpec(spec); err == nil {
		t.Fatal("expected default route to be rejected for relay-only gateway")
	}
}
