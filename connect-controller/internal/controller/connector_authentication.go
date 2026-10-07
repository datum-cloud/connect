package controller

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
)

const (
	connectorUIDLabel          = "connect.datumapis.com/connector-uid-hash"
	connectorProjectAnnotation = "connect.datumapis.com/consumer-project"
	connectorIdentityFinalizer = "connect.datumapis.com/platform-identity"
)

type ConnectorIdentityConfig struct {
	Project       string
	KeyNamespace  string
	RoleName      string
	RoleNamespace string
}

func parseRSAPublicKey(value string) (*rsa.PublicKey, error) {
	if len(value) > 8192 {
		return nil, fmt.Errorf("public key exceeds 8192 bytes")
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("must contain exactly one PEM public key")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		parsed, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("PEM block must be PUBLIC KEY or RSA PUBLIC KEY")
	}
	if err != nil {
		return nil, fmt.Errorf("parse RSA public key: %w", err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key must be RSA")
	}
	if publicKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA public key must be at least 2048 bits")
	}
	if publicKey.N.BitLen() > 4096 {
		return nil, fmt.Errorf("RSA public key must be at most 4096 bits")
	}
	return publicKey, nil
}

func validateConnectorAuthentication(connector *connectv1alpha1.Connector) error {
	if connector.UID == "" {
		return fmt.Errorf("metadata.uid must be assigned before provisioning authentication")
	}
	_, err := parseRSAPublicKey(connector.Spec.Authentication.PublicKey)
	return err
}

func connectorIdentityName(uid types.UID) string {
	sum := sha256.Sum256([]byte(uid))
	return "connect-" + hex.EncodeToString(sum[:10])
}

func connectorAuthenticationKeyName(uid types.UID) string {
	sum := sha256.Sum256([]byte(string(uid) + "\x00authentication"))
	return "connect-key-" + hex.EncodeToString(sum[:10])
}

func connectorUIDHash(uid types.UID) string {
	sum := sha256.Sum256([]byte(uid))
	return hex.EncodeToString(sum[:20])
}

func ensureConnectorIdentity(ctx context.Context, consumerClient, identityClient client.Client, config ConnectorIdentityConfig, consumerProject string, connector *connectv1alpha1.Connector) (bool, string, string, error) {
	identityName := connectorIdentityName(connector.UID)
	uidHash := connectorUIDHash(connector.UID)
	serviceAccount := &iamv1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: identityName}}
	_, err := controllerutil.CreateOrUpdate(ctx, identityClient, serviceAccount, func() error {
		if owner := serviceAccount.Labels[connectorUIDLabel]; owner != "" && owner != uidHash {
			return fmt.Errorf("service account %q is already bound to another Connector UID", identityName)
		}
		if serviceAccount.Labels == nil {
			serviceAccount.Labels = map[string]string{}
		}
		serviceAccount.Labels[connectorUIDLabel] = uidHash
		if serviceAccount.Annotations == nil {
			serviceAccount.Annotations = map[string]string{}
		}
		serviceAccount.Annotations["connect.datumapis.com/connector-name"] = connector.Name
		serviceAccount.Annotations[connectorProjectAnnotation] = consumerProject
		serviceAccount.Spec.State = "Active"
		return nil
	})
	if err != nil {
		return false, "IdentityProvisioningFailed", "could not reconcile the Connector service account", err
	}
	status := &connectv1alpha1.ConnectorAuthenticationStatus{
		ConnectorUID: string(connector.UID),
		PrincipalRef: connectv1alpha1.ConnectorPrincipalReference{Project: config.Project, Name: identityName, UID: string(serviceAccount.UID)},
	}
	connector.Status.Authentication = status
	if !meta.IsStatusConditionTrue(serviceAccount.Status.Conditions, "Ready") || serviceAccount.Status.ClientID == "" || serviceAccount.Status.Email == "" {
		return false, "IdentityProvisioning", "waiting for the Connector service account to be ready with client ID and email", nil
	}
	status.PrincipalRef.ClientID = serviceAccount.Status.ClientID
	status.PrincipalRef.ClientEmail = serviceAccount.Status.Email
	if err := ensureConnectorPolicyBinding(ctx, consumerClient, config, connector, serviceAccount); err != nil {
		return false, "AuthorizationProvisioningFailed", "could not bind the platform principal to its Connector", err
	}
	var lease coordinationv1.Lease
	if err := consumerClient.Get(ctx, types.NamespacedName{Name: connectorLeaseName(connector.Name), Namespace: connector.Namespace}, &lease); err != nil {
		return false, "AuthorizationProvisioningFailed", "could not read the Connector liveness Lease", err
	}
	if err := ensureExactPolicyBinding(ctx, consumerClient, config, connector, serviceAccount, identityName+"-lease", iamv1alpha1.ResourceReference{APIGroup: coordinationv1.GroupName, Kind: "Lease", Name: lease.Name, UID: string(lease.UID), Namespace: lease.Namespace}); err != nil {
		return false, "AuthorizationProvisioningFailed", "could not bind the platform principal to its liveness Lease", err
	}

	var keys identityv1alpha1.ServiceAccountKeyList
	keys.SetGroupVersionKind(identityv1alpha1.SchemeGroupVersion.WithKind("ServiceAccountKeyList"))
	if err := identityClient.List(ctx, &keys, client.InNamespace(config.KeyNamespace), client.MatchingLabels{connectorUIDLabel: uidHash}); err != nil {
		return false, "IdentityProvisioningFailed", "could not list Connector authentication keys", err
	}
	sort.Slice(keys.Items, func(i, j int) bool { return keys.Items[i].Name < keys.Items[j].Name })
	var registered *identityv1alpha1.ServiceAccountKey
	deletionPending := false
	for index := range keys.Items {
		item := &keys.Items[index]
		item.SetGroupVersionKind(identityv1alpha1.SchemeGroupVersion.WithKind("ServiceAccountKey"))
		matches := item.Spec.ServiceAccountUserName == serviceAccount.Status.Email && item.Spec.PublicKey == connector.Spec.Authentication.PublicKey
		if matches && registered == nil {
			registered = item
			continue
		}
		if err := identityClient.Delete(ctx, item); err != nil && !apierrors.IsNotFound(err) {
			return false, "IdentityProvisioningFailed", "could not revoke an unexpected Connector authentication key", err
		}
		deletionPending = true
	}
	if deletionPending {
		return false, "IdentityProvisioning", "waiting for unexpected authentication keys to be removed", nil
	}
	if registered == nil {
		registered = &identityv1alpha1.ServiceAccountKey{
			TypeMeta:   metav1.TypeMeta{APIVersion: identityv1alpha1.SchemeGroupVersion.String(), Kind: "ServiceAccountKey"},
			ObjectMeta: metav1.ObjectMeta{Name: connectorAuthenticationKeyName(connector.UID), Namespace: config.KeyNamespace, Labels: map[string]string{connectorUIDLabel: uidHash}, Annotations: map[string]string{connectorProjectAnnotation: consumerProject}},
			Spec:       identityv1alpha1.ServiceAccountKeySpec{ServiceAccountUserName: serviceAccount.Status.Email, PublicKey: connector.Spec.Authentication.PublicKey},
		}
		if err := identityClient.Create(ctx, registered); err != nil {
			return false, "IdentityProvisioningFailed", "could not register the Connector authentication key", err
		}
	}
	status.ServiceAccountKeyRef = registered.Name
	status.AuthProviderKeyID = registered.Status.AuthProviderKeyID
	if status.AuthProviderKeyID == "" {
		return false, "IdentityProvisioning", "waiting for the authentication key to be registered by the identity provider", nil
	}
	return true, "IdentityReady", "Connector service account and authentication key are ready", nil
}

func ensureConnectorPolicyBinding(ctx context.Context, consumerClient client.Client, config ConnectorIdentityConfig, connector *connectv1alpha1.Connector, serviceAccount *iamv1alpha1.ServiceAccount) error {
	return ensureExactPolicyBinding(ctx, consumerClient, config, connector, serviceAccount, connectorIdentityName(connector.UID), iamv1alpha1.ResourceReference{APIGroup: connectv1alpha1.GroupVersion.Group, Kind: "Connector", Name: connector.Name, UID: string(connector.UID), Namespace: connector.Namespace})
}

func ensureExactPolicyBinding(ctx context.Context, consumerClient client.Client, config ConnectorIdentityConfig, connector *connectv1alpha1.Connector, serviceAccount *iamv1alpha1.ServiceAccount, name string, resourceRef iamv1alpha1.ResourceReference) error {
	binding := &iamv1alpha1.PolicyBinding{}
	key := types.NamespacedName{Name: name, Namespace: connector.Namespace}
	err := consumerClient.Get(ctx, key, binding)
	if apierrors.IsNotFound(err) {
		binding = &iamv1alpha1.PolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: connector.Namespace, Labels: map[string]string{connectorUIDLabel: connectorUIDHash(connector.UID)}},
			Spec: iamv1alpha1.PolicyBindingSpec{
				RoleRef:          iamv1alpha1.RoleReference{Name: config.RoleName, Namespace: config.RoleNamespace},
				Subjects:         []iamv1alpha1.Subject{{Kind: "ServiceAccount", Name: serviceAccount.Name, UID: string(serviceAccount.UID)}},
				ResourceSelector: iamv1alpha1.ResourceSelector{ResourceRef: &resourceRef},
			},
		}
		if err := controllerutil.SetControllerReference(connector, binding, schemeForConnector()); err != nil {
			return err
		}
		return consumerClient.Create(ctx, binding)
	}
	if err != nil {
		return err
	}
	ref := binding.Spec.ResourceSelector.ResourceRef
	if binding.Spec.RoleRef.Name != config.RoleName || binding.Spec.RoleRef.Namespace != config.RoleNamespace || len(binding.Spec.Subjects) != 1 || binding.Spec.Subjects[0].Kind != "ServiceAccount" || binding.Spec.Subjects[0].Name != serviceAccount.Name || binding.Spec.Subjects[0].UID != string(serviceAccount.UID) || ref == nil || *ref != resourceRef {
		return fmt.Errorf("policy binding %q does not match the immutable Connector identity", name)
	}
	return nil
}

// cleanupConnectorIdentity revokes grants and platform-owned credentials. It
// returns complete only after every security object has been observed absent.
func cleanupConnectorIdentity(ctx context.Context, consumerClient, identityClient client.Client, config ConnectorIdentityConfig, connector *connectv1alpha1.Connector) (bool, error) {
	name := connectorIdentityName(connector.UID)
	bindings := []*iamv1alpha1.PolicyBinding{{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: connector.Namespace}}, {ObjectMeta: metav1.ObjectMeta{Name: name + "-lease", Namespace: connector.Namespace}}}
	for _, binding := range bindings {
		if err := consumerClient.Delete(ctx, binding); err != nil && !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("delete Connector policy binding %q: %w", binding.Name, err)
		}
	}
	serviceAccount := &iamv1alpha1.ServiceAccount{}
	serviceAccountKey := types.NamespacedName{Name: name}
	if err := identityClient.Get(ctx, serviceAccountKey, serviceAccount); err == nil {
		if serviceAccount.Spec.State != "Inactive" {
			serviceAccount.Spec.State = "Inactive"
			if err := identityClient.Update(ctx, serviceAccount); err != nil {
				return false, fmt.Errorf("deactivate Connector service account: %w", err)
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("get Connector service account: %w", err)
	}
	var keys identityv1alpha1.ServiceAccountKeyList
	keys.SetGroupVersionKind(identityv1alpha1.SchemeGroupVersion.WithKind("ServiceAccountKeyList"))
	if err := identityClient.List(ctx, &keys, client.InNamespace(config.KeyNamespace), client.MatchingLabels{connectorUIDLabel: connectorUIDHash(connector.UID)}); err != nil {
		return false, fmt.Errorf("list Connector authentication keys: %w", err)
	}
	for i := range keys.Items {
		keys.Items[i].SetGroupVersionKind(identityv1alpha1.SchemeGroupVersion.WithKind("ServiceAccountKey"))
		if err := identityClient.Delete(ctx, &keys.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("delete Connector authentication key: %w", err)
		}
	}
	complete := true
	for _, binding := range bindings {
		if err := consumerClient.Get(ctx, client.ObjectKeyFromObject(binding), &iamv1alpha1.PolicyBinding{}); err == nil {
			complete = false
		} else if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("confirm Connector policy binding %q deletion: %w", binding.Name, err)
		}
	}
	keys = identityv1alpha1.ServiceAccountKeyList{}
	keys.SetGroupVersionKind(identityv1alpha1.SchemeGroupVersion.WithKind("ServiceAccountKeyList"))
	if err := identityClient.List(ctx, &keys, client.InNamespace(config.KeyNamespace), client.MatchingLabels{connectorUIDLabel: connectorUIDHash(connector.UID)}); err != nil {
		return false, fmt.Errorf("confirm Connector authentication key deletion: %w", err)
	}
	if len(keys.Items) != 0 {
		complete = false
	} else if err := identityClient.Delete(ctx, &iamv1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("delete Connector service account: %w", err)
	}
	if err := identityClient.Get(ctx, serviceAccountKey, &iamv1alpha1.ServiceAccount{}); err == nil {
		complete = false
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("confirm Connector service account deletion: %w", err)
	}
	return complete, nil
}
