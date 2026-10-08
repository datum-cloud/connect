# Connect API and controller

This module defines the Connect-owned `connect.datumapis.com/v1alpha1` API and
the Milo multi-cluster controller. The controller provisions VPC gateways and
bindings; the Rust daemon and `datumctl` plugin consume the binding API.

## Resource ownership

`ConnectorClass` is cluster-scoped platform configuration in the management
cluster. `ConnectGatewayClass` is installed cluster-wide in each entitled
project; it names this controller, describes its observable lifecycle policy,
and references an operator-owned ConfigMap in the controller cluster for
private implementation parameters such as the gateway image and Compute
instance type. `Connector`, `ConnectorAdvertisement`, and `ConnectGateway` are
project resources and carry Milo's
`discovery.miloapis.com/parent-contexts=Project` annotation. The controller
uses `go.miloapis.com/milo/pkg/multicluster-runtime/milo` and registers these
project controllers with `WithEngageWithLocalCluster(false)`.

The controller provisions the first single-project CONNECT-IP gateway slice:

- ConnectorClass reports whether its transport configuration is valid.
- Connector atomically supplies distinct immutable identities in
  `spec.transport.publicKey` (iroh transport) and
  `spec.authentication.publicKey` (RSA control-plane authentication). It
  resolves its class from the management cluster and reports Accepted when the
  class advertises `masque-v1`. The controller provisions one Milo
  ServiceAccount derived from
  the immutable Connector UID in the configured platform identity project and
  registers only client-supplied public keys there. The consumer project holds
  only an exact-UID PolicyBinding and the Connector status reference. It then
  creates a 30-second project Lease and reports Ready only while the agent
  renews that Lease.
- ConnectorAdvertisement is accepted only when its Connector is ready and its
  service protocol/port fields are valid.
- ConnectGateway selects a ConnectGatewayClass and creates a stable private
  gateway key plus a ConfigMap containing the gateway's durable peer grants.
  An `AlwaysOn` class maintains a one-replica Compute Workload. An `OnDemand`
  class creates it while a non-deleting binding targets an Accepted and Ready
  Connector, then deletes only the Workload after the class idle timeout.
  Binding readiness is not used as the activity signal because it depends on
  Workload availability. Compute creates the NSO NetworkBinding for the
  Workload interface. The gateway does not create a competing binding.
  Its Prometheus endpoint binds to `127.0.0.1:9090`; the controller does not
  expose a metrics port on the VPC interface.
- ConnectNetworkBinding attaches one project Connector to a ConnectGateway.
  Project authorization to create the resource is the approval boundary. The
  controller derives matching `/128` peer addresses and routes, then reconciles
  an approved peer grant into the gateway ConfigMap. Deleting the binding
  removes the grant on the next reconciliation.
- `ConnectGateway.spec.peerRouting` optionally adds every other ready Connector's
  assigned `/128` to each binding and gateway grant. It is disabled by default.
  Peer packets are forwarded between authenticated gateway sessions without
  entering the VPC or its NAT path. VPC and peer routes together are limited to
  32 routes per Connector.
- ConnectGatewayClass status reports whether the class is accepted and its
  operator parameters are ready. ConnectGateway status publishes its resolved
  class, operational phase, stable endpoint ID, idle timestamp, and current
  Workload name. A stopped OnDemand gateway reports `Dormant`; Ready becomes
  true only after the Compute Workload is Available. This reports workload
  availability, not a working packet path.

For gateway diagnostics, exec into the gateway Workload and query
`http://127.0.0.1:9090/metrics`. CONNECT-IP counters show active/opened
sessions, transport errors, drops, datagrams, MTU capacity, and packet/byte
totals in each direction. Structured gateway logs include the client-provided
`session_id`; correlate that ID with the daemon logs. Set
`DATUM_CONNECT_OTEL_ENDPOINT` on the gateway process to export correlated
OpenTelemetry traces to a trusted OTLP/HTTP collector.

The gateway private key is stored in a project Secret and mounted read-only in
the Compute Workload; status exposes only its public endpoint ID. The Connect
agent must be authorized to renew the Connector's project Lease. The
exact-Connector binding is implemented here; ownership-aware authorization for
future child-resource creation remains a platform admission dependency.

## Connector control-plane authentication

The client generates the iroh key and a distinct 2048- to 4096-bit RSA key
before creation, stores both private keys locally, and submits both public keys
in the single Connector create. The API makes both public keys immutable. Key
rotation or recovery therefore replaces the Connector; there is no secondary
enrollment object or client-selected authentication key ID.

The controller waits for the platform ServiceAccount to report `Ready=True`
with both `status.clientID` and `status.email`, then publishes them separately
in `status.authentication` with the ServiceAccountKey auth-provider key ID.
`clientID` is the credential `client_id` and JWT `iss`/`sub`; `clientEmail` is
the credential `client_email`; and `authProviderKeyID` is `private_key_id` and
JWT `kid`. The service account name is derived from the Connector UID rather
than its reusable resource name, but its UID is never used as the OAuth client
ID.

Ordinary Connector updates cannot add or rotate authentication keys because
the authentication public key is immutable. Clients use atomic identity
creation only when their ConnectorClass advertises the
`connector-authentication` capability. Operators must not advertise it until
the token endpoint and UID-scoped access policy described below are live.
Configure `--identity-project` with a platform-controlled project distinct from
every consumer project. Milo must enable ServiceAccountKeys there and accept
client-supplied RSA public keys. The controller creates an exact-resource
PolicyBinding in the consumer project using the pre-provisioned role selected by
`--connector-agent-role-*`; it never grants project-wide Connect Admin. Milo's
current PolicyBinding API cannot express a name-scoped create grant for future
ConnectorAdvertisement or ConnectNetworkBinding resources, so the platform role
and admission layer must provide ownership-aware child-resource authorization
before advertising the capability. The deletion finalizer removes the binding,
keys, and ServiceAccount before deletion completes. It remains on
the Connector until each security object has been observed `NotFound`; merely
accepting asynchronous delete requests is not considered successful revocation.

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

## Migration status

This is a clean, breaking `v1alpha1` schema change. Preview Connectors using the
old flat transport fields or a separate authentication bootstrap resource must
be deleted and recreated. There are no deprecated aliases or conversion paths.

This is a new API group, not an in-place change to NSO's
`networking.datumapis.com` resources. `datumctl connect join` discovers a
gateway for the Network or creates one in the nearest location using the Ready
default `ConnectGatewayClass`, then creates or reuses a `ConnectNetworkBinding`
for the current Connector. Enrollment, peer discovery, and service advertisements use
Connect `Connector` and `ConnectorAdvertisement` resources. Explicit public
ingress still uses NSO's HTTPProxy API. No conversion webhook or automatic
resource copy exists; keep the NSO Network and HTTPProxy APIs available for
those remaining cross-service contracts.

The Network reference remains a name-only cross-service reference because
Network is NSO-owned. The controller reconciles a gateway into a Compute
Workload, and the daemon consumes the resulting binding status. A staging
deployment needs a gateway image with the matching CONNECT-IP transport and
Compute runtime support for IPv6 forwarding and `NET_ADMIN`.

For a local multi-device data-plane validation, build the Linux daemon, plugin,
and gateway binaries into `target/connect-ip-linux-bin`, build the lab image
from `scripts/connect-vpc-multi-device.Dockerfile`, and run:

```sh
python3 scripts/connect-vpc-multi-device-local.py \
  --docker-context colima \
  --binaries target/connect-ip-linux-bin
```

The disposable lab enrolls two real daemons, attaches both concurrently to one
gateway, and verifies ICMP, TCP, and UDP both across the gateway's IPv6 VPC
packet path and directly between the devices. Cloud authorization is simulated;
TUN devices, iroh sessions, forwarding, and packets are real.

The intended staging resources look like this:

```yaml
apiVersion: connect.datumapis.com/v1alpha1
kind: ConnectGatewayClass
metadata:
  name: standard
spec:
  controllerName: connect.datum.net/gateway-controller
  default: true
  relayURLs:
    - https://iroh-relay.us-central-1.datum-staging.net
    - https://iroh-relay.us-east-1.datum-staging.net
  parametersRef:
    namespace: connect-system
    name: standard-gateway
  scaling:
    mode: OnDemand
    idleTimeout: 10m
---
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: connect-system
  name: standard-gateway
data:
  image: ghcr.io/datum-cloud/iroh-gateway:<connect-ip-build>
  instanceType: datumcloud/d1-standard-2
---
apiVersion: connect.datumapis.com/v1alpha1
kind: ConnectGateway
metadata:
  name: staging-vpc
spec:
  gatewayClassRef: standard
  networkRef: staging-vpc
  locationRef: DFW
  routes: [fd20:0:27::/48]
  peerRouting: true
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
status publishes the client and gateway `/128` addresses, gateway endpoint ID,
configured routes, and relay URLs. Use an image and relay that match the daemon's
CONNECT-IP transport. Do not use placeholder values in a staging deployment.
