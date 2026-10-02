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

The controller provisions the first single-project CONNECT-IP gateway slice:

- ConnectorClass reports whether its transport configuration is valid.
- Connector checks its hex public key and resolves its class from the
  management cluster. It reports Accepted when the class advertises
  `masque-v1`, then creates a 30-second project Lease and reports Ready only
  while the agent renews that Lease.
- ConnectorAdvertisement is accepted only when its Connector is ready and its
  service protocol/port fields are valid.
- ConnectGateway creates a stable private gateway key, a ConfigMap containing
  the gateway's peer grants, and a one-replica Compute Workload attached to the
  requested IPv6 Network and Location. Compute creates the NSO NetworkBinding
  for the Workload interface. The gateway does not create a competing binding.
- ConnectNetworkBinding attaches one project Connector to a ConnectGateway.
  Project authorization to create the resource is the approval boundary. The
  controller derives matching `/128` peer addresses and routes, then reconciles
  an approved peer grant into the gateway ConfigMap. Deleting the binding
  removes the grant on the next reconciliation.
- ConnectGateway status publishes the gateway endpoint ID and Workload name.
  Ready becomes true after the Compute Workload is Available. This reports
  instance availability, not an active tunnel; clients still need to resolve
  the endpoint and submit a ConnectNetworkBinding.

The gateway private key is stored in a project Secret and mounted read-only in
the Compute Workload; status exposes only its public endpoint ID. The Connect
agent must be authorized to renew the Connector's project Lease. Connector
resource authorization and agent-side Lease renewal are not implemented by this
module. Connector key rotation and deletion semantics remain resource
replacement/deletion and must be wired into the enrollment client before
production use.

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

The Network reference remains a name-only cross-service reference because
Network is NSO-owned. Compute Workload integration is now implemented, but
the local daemon still resolves peers through the existing NSO Connector API,
so the new ConnectGateway endpoint is not yet consumable by `datumctl connect
join`. The plugin/daemon migration must create a ConnectNetworkBinding before
this API can support the desired one-command user flow. Staging also needs an
iroh-gateway image built with the sibling Connect transport crates, plus
Compute/runtime support for IPv6 forwarding and `NET_ADMIN`.

The intended staging resources look like this:

```yaml
apiVersion: connect.datumapis.com/v1alpha1
kind: ConnectGateway
metadata:
  name: staging-vpc
spec:
  networkRef: staging-vpc
  locationRef: DFW
  routes: [fd20:0:27::/48]
  image: ghcr.io/datum-cloud/iroh-gateway:<connect-ip-build>
  relayURLs: [https://<staging-relay-host>]
---
apiVersion: connect.datumapis.com/v1alpha1
kind: ConnectNetworkBinding
metadata:
  name: laptop-staging-vpc
spec:
  gatewayRef: staging-vpc
  connectorRef: laptop
```

Creating the ConnectNetworkBinding is the project authorization boundary. Its
status publishes the matching client/gateway `/128` addresses, gateway endpoint
ID, configured routes, and relay URLs. Do not use a placeholder relay or image
tag in staging; the gateway image must contain the current CONNECT-IP ALPN and
MASQUE-over-QUIC-DATAGRAM implementation.
