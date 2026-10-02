# Connect API and controller

This module introduces the Connect-owned `connect.datumapis.com/v1alpha1` API
and the Milo multi-cluster controller. It is deliberately separate from the
Rust daemon and `datumctl` plugin.

## Resource ownership

`ConnectorClass` is cluster-scoped platform configuration, matching the scope
of the current NSO ConnectorClass. `Connector`, `ConnectorAdvertisement`, and
`ConnectGateway` are project resources and carry Milo's
`discovery.miloapis.com/parent-contexts=Project` annotation. The controller
uses `go.miloapis.com/milo/pkg/multicluster-runtime/milo` and registers these
project controllers with `WithEngageWithLocalCluster(false)`.

The first reconciliation slice is intentionally bounded:

- ConnectorClass reports whether its transport configuration is valid.
- Connector checks its hex public key and resolves its class from the
  management cluster. It reports Accepted when the class advertises
  `masque-v1`, then creates a 30-second project Lease and reports Ready only
  while the agent renews that Lease.
- ConnectorAdvertisement is accepted only when its Connector is ready and its
  service protocol/port fields are valid.
- ConnectGateway is an API intent only. Its status explicitly reports
  `IntegrationPending` until NSO NetworkBinding and Compute Workload integration
  exists. It does not deploy a gateway, create a NetworkBinding, or alter routes.

The controller stores no private key or credential. The Connect agent must be
authorized to renew the Connector's project Lease; resource authorization and
the agent-side Lease renewal are not implemented by this module. Connector key
rotation and deletion semantics remain resource replacement/deletion and must
be wired into the enrollment client before production use.

## Install and run

The deployment follows Compute's controller-runtime layout. Build and render
locally:

```sh
make test manifests build deploy-render
```

For local single-cluster development, run with a kubeconfig that can read
Milo's Project and ProjectControlPlane discovery resources and access project
control planes:

```sh
go run ./cmd/controller --discovery-kubeconfig ~/.kube/config \
  --project-kubeconfig ~/.kube/config
```

For a cluster deployment, update the image in `config/base/manager/deployment.yaml`
to the published controller image and apply `config/default`. The service
account needs Milo project discovery permissions in the management cluster;
project kubeconfig credentials must also authorize Connect resource watches,
status updates, and Lease creation/renewal in each project control plane. Set
`--internal-service-discovery=true` only when ProjectControlPlane resources
provide internal service addresses.

The liveness/readiness endpoints use port 8081. The metrics endpoint uses port
8080 and should be scraped only inside the cluster. The controller runs as a
non-root user with a read-only root filesystem and leader election enabled.

## API migration

This is a new API group, not an in-place change to NSO's
`networking.datumapis.com` resources. The current Connect Rust library and CLI
still use NSO's Connector APIs, so this controller does not yet replace those
resources or make the current CLI use this API. No conversion webhook or
automatic resource copy is included. Before rollout, publish the Connect CRDs
and APIs, update clients and service authorization, then run an explicit
inventory/copy/cutover for existing Connector, ConnectorClass, and
ConnectorAdvertisement objects. Keep NSO serving the old API until every
consumer has migrated and rollback is no longer required.

`ConnectGateway` has no production network behavior yet. Its Network reference
is a name-only cross-service reference because Network and NetworkBinding
remain NSO-owned; location and workload placement ownership also needs a
Compute integration design.
