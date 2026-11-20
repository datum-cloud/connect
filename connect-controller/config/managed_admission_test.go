package config_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	admission "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

func TestManagedAdmissionDirectAPI(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI must provide real envtest assets for managed admission")
		}
		t.Skip("real API requires KUBEBUILDER_ASSETS")
	}
	environment := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("base", "crd", "bases")}}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{connect.AddToScheme, corev1.AddToScheme, admission.AddToScheme, rbacv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := admin.Create(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "admission-test-only"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{"connect.datumapis.com"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "admission-test-only"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admission-test-only"}, Subjects: []rbacv1.Subject{{Kind: "Group", APIGroup: rbacv1.GroupName, Name: "admission-test-only"}}}); err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"service", "other"} {
		if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
			t.Fatal(err)
		}
	}
	policy := &admission.ValidatingAdmissionPolicy{}
	binding := &admission.ValidatingAdmissionPolicyBinding{}
	for file, object := range map[string]client.Object{"policy.yaml": policy, "binding.yaml": binding} {
		encoded, err := os.ReadFile(filepath.Join("components", "managed-endpoints", "admission", file))
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(encoded, object); err != nil {
			t.Fatal(err)
		}
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	endpoint := func(name, namespace string) *connect.ConnectEndpoint {
		return &connect.ConnectEndpoint{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"iam.miloapis.com/parent-name": "service-project"}}, Spec: connect.ConnectEndpointSpec{CustomerProjectUID: "customer", CustomerProject: "service-project", GatewayUID: "gateway", GatewayNamespace: "default", GatewayName: "gateway", Metro: "central", Hostname: name + ".example.test", Lifecycle: "Active"}}
	}
	extra := func(project string) map[string][]string {
		return map[string][]string{"iam.miloapis.com/parent-type": {"Project"}, "iam.miloapis.com/parent-name": {project}, "iam.miloapis.com/parent-api-group": {"resourcemanager.miloapis.com"}}
	}
	actor := func(username, uid string, context map[string][]string) client.Client {
		copy := rest.CopyConfig(config)
		copy.Impersonate = rest.ImpersonationConfig{UserName: username, UID: uid, Groups: []string{"admission-test-only"}, Extra: context}
		result, err := client.New(copy, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	writer := actor("controller@service-project.identity.miloapis.com", "writer-incarnation", extra("service-project"))
	denied := func(err error) bool {
		return err != nil && (apierrors.IsForbidden(err) || apierrors.IsInvalid(err)) && strings.Contains(err.Error(), "ValidatingAdmissionPolicy 'connect-managed-service-scope'")
	}
	await := func(check func() bool) {
		t.Helper()
		if err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 15*time.Second, true, func(context.Context) (bool, error) { return check(), nil }); err != nil {
			t.Fatal("admission did not converge", err)
		}
	}
	await(func() bool {
		err := writer.Create(ctx, endpoint("default-denied", "service"), client.DryRunAll)
		if !denied(err) {
			t.Logf("default-deny admission pending: %v", err)
		}
		return denied(err)
	})
	if err := admin.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	for index, variable := range policy.Spec.Variables {
		switch variable.Name {
		case "serviceProject":
			policy.Spec.Variables[index].Expression = "'service-project'"
		case "serviceNamespace":
			policy.Spec.Variables[index].Expression = "'service'"
		case "writer":
			policy.Spec.Variables[index].Expression = "'controller@service-project.identity.miloapis.com'"
		case "writerUID":
			policy.Spec.Variables[index].Expression = "'writer-incarnation'"
		}
	}
	if err := admin.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	await(func() bool {
		err := writer.Create(ctx, endpoint("allowed-dry-run", "service"), client.DryRunAll)
		if err != nil {
			t.Logf("authorized admission pending: %v", err)
		}
		return err == nil
	})
	reservation := endpoint("reservation", "service")
	if err := writer.Create(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	grant := &connect.ConnectGrant{ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "service"}, Spec: connect.ConnectGrantSpec{NetworkName: "network", NetworkUID: "network", VPC: connect.EndpointVPCReference{Namespace: "vpcs", Name: "network", UID: "vpc"}, EndpointName: reservation.Name, EndpointUID: string(reservation.UID), BindingName: "binding", BindingUID: "binding", PolicyRevision: "policy", ConnectorID: "connector", Cell: "central"}}
	if err := writer.Create(ctx, grant); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"customer-writer", "recreated-writer", "missing-uid", "other-project", "missing-context", "ambiguous-project", "ambiguous-kind", "wrong-kind", "missing-group", "wrong-group", "ambiguous-group", "wrong-namespace"} {
		t.Run(scenario, func(t *testing.T) {
			username, uid, namespace, values := "controller@service-project.identity.miloapis.com", "writer-incarnation", "service", extra("service-project")
			switch scenario {
			case "customer-writer":
				username = "customer"
			case "recreated-writer":
				uid = "replacement-incarnation"
			case "missing-uid":
				uid = ""
			case "other-project":
				values = extra("customer-project")
			case "missing-context":
				values = nil
			case "ambiguous-project":
				values["iam.miloapis.com/parent-name"] = []string{"service-project", "customer-project"}
			case "ambiguous-kind":
				values["iam.miloapis.com/parent-type"] = []string{"Project", "Project"}
			case "wrong-kind":
				values["iam.miloapis.com/parent-type"] = []string{"Organization"}
			case "missing-group":
				delete(values, "iam.miloapis.com/parent-api-group")
			case "wrong-group":
				values["iam.miloapis.com/parent-api-group"] = []string{"other.example"}
			case "ambiguous-group":
				values["iam.miloapis.com/parent-api-group"] = []string{"resourcemanager.miloapis.com", "other.example"}
			case "wrong-namespace":
				namespace = "other"
			}
			requester := actor(username, uid, values)
			for _, options := range [][]client.CreateOption{nil, {client.DryRunAll}} {
				if err := requester.Create(ctx, endpoint("spoofed", namespace), options...); !denied(err) {
					t.Fatalf("unauthorized create: %v", err)
				}
				copy := grant.DeepCopy()
				copy.Name = "spoofed"
				copy.Namespace = namespace
				copy.ResourceVersion = ""
				copy.UID = ""
				if err := requester.Create(ctx, copy, options...); !denied(err) {
					t.Fatalf("unauthorized grant create: %v", err)
				}
			}
			if scenario != "wrong-namespace" {
				copy := reservation.DeepCopy()
				copy.Spec.Lifecycle = "Deleting"
				if err := requester.Update(ctx, copy); !denied(err) {
					t.Fatalf("unauthorized update: %v", err)
				}
				if err := requester.Status().Update(ctx, copy); !denied(err) {
					t.Fatalf("unauthorized status: %v", err)
				}
				if err := requester.Status().Update(ctx, grant.DeepCopy()); !denied(err) {
					t.Fatalf("unauthorized grant status: %v", err)
				}
				if err := requester.Update(ctx, grant.DeepCopy(), client.DryRunAll); !denied(err) {
					t.Fatalf("unauthorized grant update dry-run: %v", err)
				}
				for _, object := range []client.Object{reservation.DeepCopy(), grant.DeepCopy()} {
					if err := requester.Patch(ctx, object, client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"labels":{"iam.miloapis.com/parent-name":"service-project"}}}`))); !denied(err) {
						t.Fatalf("unauthorized patch: %v", err)
					}
					if err := requester.Status().Update(ctx, object, client.DryRunAll); !denied(err) {
						t.Fatalf("unauthorized status dry-run: %v", err)
					}
				}
			}
		})
	}
	reservation.Spec.Lifecycle = "Deleting"
	if err := writer.Update(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	reservation.Status.CleanupStep = "Done"
	if err := writer.Status().Update(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	reservation.Spec.Lifecycle = "Retired"
	if err := writer.Update(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"Active", "Retiring", "Retired"} {
		grant.Status.State = state
		if err := writer.Status().Update(ctx, grant); err != nil {
			t.Fatal(err)
		}
	}
	for _, object := range []client.Object{reservation, grant} {
		if err := writer.Delete(ctx, object); !denied(err) {
			t.Fatalf("tombstone delete accepted: %v", err)
		}
		if err := writer.DeleteAllOf(ctx, object, client.InNamespace("service")); !denied(err) {
			t.Fatalf("collection delete accepted: %v", err)
		}
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.Variables[2].Expression = "request.userInfo.extra['unavailable-guard-configuration'][0]"
	if err := admin.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	await(func() bool {
		return denied(writer.Create(ctx, endpoint("guard-failed", "service"), client.DryRunAll))
	})
}
