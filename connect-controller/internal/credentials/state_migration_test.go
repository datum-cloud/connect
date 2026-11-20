package credentials

import (
	"context"
	"testing"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGrantRevocationPersistsBeforeUnavailableAuthority(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = connect.AddToScheme(scheme)
	for _, legacy := range []connect.ConnectGrantStatus{{}, {Retiring: true}, {Retired: true}, {State: "Active", Retiring: true}, {State: "Active", Retired: true}} {
		receipt := &connect.ConnectGrant{ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "service"}, Spec: connect.ConnectGrantSpec{Cell: "selected", ConnectorID: "connector"}, Status: legacy}
		project := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&connect.ConnectGrant{}).WithObjects(receipt).Build()
		issuer := &ManagedIssuer{Project: project}
		if err := issuer.Retire(ctx, receipt); err == nil {
			t.Fatal("missing selected authority was ignored")
		}
		if err := project.Get(ctx, client.ObjectKeyFromObject(receipt), receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.Status.EffectiveState() == "Active" {
			t.Fatal("revocation failure left grant mintable")
		}
		authority := &authorityFixture{project: project}
		issuer.Authorities = map[string]GrantAPI{"selected": authority}
		if err := issuer.Retire(ctx, receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.Status.State != "Retired" || receipt.Status.Retired || receipt.Status.Retiring || authority.retired != 1 {
			t.Fatal("legacy tombstone was not safely converted")
		}
	}
}
