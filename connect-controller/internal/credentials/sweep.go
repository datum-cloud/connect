package credentials

import (
	"context"
	"time"

	connect "go.datum.net/connect-controller/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type GrantSweeper struct {
	Issuer *ManagedIssuer
	Valid  func(context.Context, *connect.ConnectGrant) (bool, error)
}

func (sweeper *GrantSweeper) Sweep(ctx context.Context) error {
	var receipts connect.ConnectGrantList
	if err := sweeper.Issuer.Project.List(ctx, &receipts, client.InNamespace(sweeper.Issuer.Namespace)); err != nil {
		return err
	}
	for index := range receipts.Items {
		receipt := &receipts.Items[index]
		if receipt.Status.EffectiveState() != "Active" {
			if err := sweeper.Issuer.Retire(ctx, receipt); err != nil {
				log.FromContext(ctx).Error(err, "reaffirm grant tombstone", "grant", receipt.Name)
			}
			continue
		}
		valid, err := sweeper.Valid(ctx, receipt)
		if err != nil {
			log.FromContext(ctx).Error(err, "check grant owner", "grant", receipt.Name)
			continue
		}
		if !valid {
			if err := sweeper.Issuer.Retire(ctx, receipt); err != nil {
				log.FromContext(ctx).Error(err, "retire grant", "grant", receipt.Name)
			}
		}
	}
	return nil
}

func (sweeper *GrantSweeper) Start(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := sweeper.Sweep(ctx); err != nil {
			log.FromContext(ctx).Error(err, "grant sweep")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (sweeper *GrantSweeper) NeedLeaderElection() bool { return true }
