package commands

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	servicesv1alpha1 "go.miloapis.com/service-catalog/api/v1alpha1"
	"go.miloapis.com/service-catalog/pkg/activation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

func TestConnectServiceGateRequired(t *testing.T) {
	for _, name := range []string{"up", "serve", "dial", "join", "ping"} {
		t.Run(name, func(t *testing.T) {
			if !connectServiceGateRequired(&cobra.Command{Use: name}) {
				t.Fatalf("%s should require Connect service access", name)
			}
		})
	}
	for _, name := range []string{"status", "down", "unserve", "hangup", "leave", "health", "doctor", "daemon", "install"} {
		t.Run(name, func(t *testing.T) {
			if connectServiceGateRequired(&cobra.Command{Use: name}) {
				t.Fatalf("%s should remain available without Connect service access", name)
			}
		})
	}
}

func TestConnectServiceActivationAlreadyActive(t *testing.T) {
	client := &fakeEntitlementClient{entitlements: activeConnectEntitlements()}
	project := "test-project"
	activationFlow := connectServiceActivation{
		resolveService: func(context.Context) (activation.ServiceInfo, error) {
			return testConnectServiceInfo(servicesv1alpha1.EnablementModeGatedByProvider), nil
		},
		newEntitlementClient: func(got string) (activation.EntitlementClient, error) {
			if got != project {
				t.Fatalf("project = %q, want %q", got, project)
			}
			return client, nil
		},
	}

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := activationFlow.run(cmd, project); err != nil {
		t.Fatalf("activation gate for active service: %v", err)
	}
	if client.creates != 0 {
		t.Fatalf("created %d entitlements for an active service", client.creates)
	}
}

func TestConnectServiceActivationEnablesSelfService(t *testing.T) {
	client := &fakeEntitlementClient{}
	activationFlow := connectServiceActivation{
		resolveService: func(context.Context) (activation.ServiceInfo, error) {
			return testConnectServiceInfo(servicesv1alpha1.EnablementModeSelfService), nil
		},
		newEntitlementClient: func(string) (activation.EntitlementClient, error) {
			return client, nil
		},
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var stderr bytes.Buffer
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)

	if err := activationFlow.run(cmd, "test-project"); err != nil {
		t.Fatalf("activation gate: %v", err)
	}
	if client.creates != 1 || client.created == nil {
		t.Fatalf("created entitlement count = %d, want 1", client.creates)
	}
	if got := client.created.Spec.ServiceRef.Name; got != "connect-datumapis-com" {
		t.Fatalf("serviceRef.name = %q", got)
	}
	for _, want := range []string{"Enabling connect", "Connect is now enabled"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr %q does not contain %q", stderr.String(), want)
		}
	}
}

func TestConnectServiceActivationRequestsProviderGatedAccess(t *testing.T) {
	client := &fakeEntitlementClient{}
	activationFlow := connectServiceActivation{
		resolveService: func(context.Context) (activation.ServiceInfo, error) {
			return testConnectServiceInfo(servicesv1alpha1.EnablementModeGatedByProvider), nil
		},
		newEntitlementClient: func(string) (activation.EntitlementClient, error) {
			return client, nil
		},
		io: func(cmd *cobra.Command) activation.IOStreams {
			return connectActivationIO(cmd).WithInteractive(true)
		},
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var stderr bytes.Buffer
	cmd.SetIn(strings.NewReader("yes\n"))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)

	if err := activationFlow.run(cmd, "test-project"); err != nil {
		t.Fatalf("activation gate: %v", err)
	}
	if client.creates != 1 {
		t.Fatalf("created entitlement count = %d, want 1", client.creates)
	}
	for _, want := range []string{"needs approval", "Would you like to request access?", "Requesting access to connect"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr %q does not contain %q", stderr.String(), want)
		}
	}
}

func testConnectServiceInfo(mode servicesv1alpha1.EnablementMode) activation.ServiceInfo {
	return activation.ServiceInfo{
		ObjectName:     "connect-datumapis-com",
		CanonicalName:  connectServiceName,
		DisplayName:    "Connect",
		EnablementMode: mode,
	}
}

func activeConnectEntitlements() *servicesv1alpha1.ServiceEntitlementList {
	return &servicesv1alpha1.ServiceEntitlementList{Items: []servicesv1alpha1.ServiceEntitlement{*activeConnectEntitlement()}}
}

func activeConnectEntitlement() *servicesv1alpha1.ServiceEntitlement {
	return &servicesv1alpha1.ServiceEntitlement{
		ObjectMeta: metav1.ObjectMeta{Name: "connect-datumapis-com", ResourceVersion: "2"},
		Spec: servicesv1alpha1.ServiceEntitlementSpec{
			ServiceRef: servicesv1alpha1.ServiceRef{Name: "connect-datumapis-com"},
		},
		Status: servicesv1alpha1.ServiceEntitlementStatus{
			Phase:       servicesv1alpha1.EntitlementPhaseActive,
			ServiceName: connectServiceName,
			Conditions: []metav1.Condition{{
				Type:   servicesv1alpha1.ConditionTypeReady,
				Status: metav1.ConditionTrue,
			}},
		},
	}
}

type fakeEntitlementClient struct {
	entitlements *servicesv1alpha1.ServiceEntitlementList
	created      *servicesv1alpha1.ServiceEntitlement
	creates      int
}

func (f *fakeEntitlementClient) List(context.Context) (*servicesv1alpha1.ServiceEntitlementList, error) {
	if f.entitlements == nil {
		return &servicesv1alpha1.ServiceEntitlementList{}, nil
	}
	return f.entitlements.DeepCopy(), nil
}

func (f *fakeEntitlementClient) Get(context.Context, string) (*servicesv1alpha1.ServiceEntitlement, error) {
	if f.created != nil {
		return activeConnectEntitlement(), nil
	}
	return nil, errors.New("unexpected Get")
}

func (f *fakeEntitlementClient) Create(_ context.Context, entitlement *servicesv1alpha1.ServiceEntitlement) error {
	f.creates++
	f.created = entitlement.DeepCopy()
	entitlement.ResourceVersion = "1"
	return nil
}

func (f *fakeEntitlementClient) Delete(context.Context, *servicesv1alpha1.ServiceEntitlement) error {
	return errors.New("unexpected Delete")
}

func (f *fakeEntitlementClient) Watch(context.Context, string, string) (watch.Interface, error) {
	watcher := watch.NewRaceFreeFake()
	watcher.Modify(activeConnectEntitlement())
	return watcher, nil
}
