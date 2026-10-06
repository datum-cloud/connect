package main

import (
	"context"
	"flag"
	"os"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
	milo "go.miloapis.com/milo/pkg/multicluster-runtime/milo"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"

	connectv1alpha1 "go.datum.net/connect-controller/api/v1alpha1"
	"go.datum.net/connect-controller/internal/controller"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(coordinationv1.AddToScheme(scheme))
	utilruntime.Must(iamv1alpha1.AddToScheme(scheme))
	utilruntime.Must(identityv1alpha1.AddToScheme(scheme))
	utilruntime.Must(connectv1alpha1.AddToScheme(scheme))
}

func main() {
	var discoveryKubeconfig, projectKubeconfig, identityProject, identityKeyNamespace, connectorAgentRoleName, connectorAgentRoleNamespace string
	var internalServiceDiscovery bool
	flag.StringVar(&discoveryKubeconfig, "discovery-kubeconfig", "", "kubeconfig for Milo project discovery (defaults to in-cluster credentials)")
	flag.StringVar(&projectKubeconfig, "project-kubeconfig", "", "kubeconfig template for project control planes (defaults to in-cluster credentials)")
	flag.BoolVar(&internalServiceDiscovery, "internal-service-discovery", false, "use internal project control-plane service addresses")
	flag.StringVar(&identityProject, "identity-project", "", "platform-controlled project that owns Connector service accounts and keys")
	flag.StringVar(&identityKeyNamespace, "identity-key-namespace", "default", "namespace for Connector ServiceAccountKey resources in the identity project")
	flag.StringVar(&connectorAgentRoleName, "connector-agent-role-name", "connect.datumapis.com-connector-agent", "pre-provisioned least-privilege role bound to each Connector principal")
	flag.StringVar(&connectorAgentRoleNamespace, "connector-agent-role-namespace", "milo-system", "namespace containing the Connector agent role")
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))

	discoveryConfig, err := restConfig(discoveryKubeconfig)
	if err != nil {
		ctrl.Log.Error(err, "load discovery config")
		os.Exit(1)
	}
	projectConfig, err := restConfig(projectKubeconfig)
	if err != nil {
		ctrl.Log.Error(err, "load project config")
		os.Exit(1)
	}

	discoveryMgr, err := manager.New(discoveryConfig, manager.Options{
		Scheme:  scheme,
		Metrics: server.Options{BindAddress: "0"},
		Cache:   cache.Options{DefaultTransform: cache.TransformStripManagedFields()},
	})
	if err != nil {
		ctrl.Log.Error(err, "create Milo discovery manager")
		os.Exit(1)
	}
	provider, err := milo.New(discoveryMgr, milo.Options{
		InternalServiceDiscovery: internalServiceDiscovery,
		ProjectRestConfig:        projectConfig,
		ClusterOptions: []cluster.Option{func(o *cluster.Options) {
			o.Scheme = scheme
			o.Cache.DefaultTransform = cache.TransformStripManagedFields()
		}},
	})
	if err != nil {
		ctrl.Log.Error(err, "create Milo project provider")
		os.Exit(1)
	}

	// Do not let multicluster-runtime leader-gate per-process project discovery.
	// Milo cluster engagement is local watch/cache setup and must run on each pod.
	mcProvider := struct{ multicluster.Provider }{provider}
	mgr, err := mcmanager.New(ctrl.GetConfigOrDie(), mcProvider, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                server.Options{BindAddress: ":8080"},
		HealthProbeBindAddress: ":8081",
		LeaderElection:         true,
		LeaderElectionID:       "connect-controller.connect.datumapis.com",
	})
	if err != nil {
		ctrl.Log.Error(err, "create controller manager")
		os.Exit(1)
	}
	if err := mgr.GetLocalManager().Add(discoveryMgr); err != nil {
		ctrl.Log.Error(err, "add discovery manager")
		os.Exit(1)
	}
	if err := mgr.GetLocalManager().Add(nonLeaderElectionRunnable{Runnable: manager.RunnableFunc(func(ctx context.Context) error { return provider.Start(ctx, mgr) })}); err != nil {
		ctrl.Log.Error(err, "add Milo provider")
		os.Exit(1)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		ctrl.Log.Error(err, "add health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		ctrl.Log.Error(err, "add readiness check")
		os.Exit(1)
	}
	if err := (&controller.ConnectReconciler{Identity: controller.ConnectorIdentityConfig{Project: identityProject, KeyNamespace: identityKeyNamespace, RoleName: connectorAgentRoleName, RoleNamespace: connectorAgentRoleNamespace}}).SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "setup Connect controllers")
		os.Exit(1)
	}
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		ctrl.Log.Error(err, "run manager")
		os.Exit(1)
	}
}

type nonLeaderElectionRunnable struct{ manager.Runnable }

func (nonLeaderElectionRunnable) NeedLeaderElection() bool { return false }

func restConfig(path string) (*rest.Config, error) {
	if path == "" {
		return ctrl.GetConfig()
	}
	return clientcmd.BuildConfigFromFlags("", path)
}
