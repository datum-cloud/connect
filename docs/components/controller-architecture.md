# Controller Architecture

The Connect controller is a Milo multicluster controller that validates
Connect-owned project resources and reconciles managed CONNECT-IP gateways. It
does not proxy application or packet traffic.

## Overview

**Key characteristics:**

- **Multicluster**: watches Project control planes discovered through Milo.
- **Declarative**: status conditions describe validation and convergence.
- **Deterministic**: stable child names, gateway identity, and peer addresses.
- **Least privilege**: controller deployment is non-root; privileged packet
  forwarding remains inside the platform gateway data plane.
- **Eventually consistent**: periodic requeues cover Lease expiry and external
  gateway-service configuration convergence.

## Architecture Diagram

```mermaid
flowchart LR
    mgmt[Milo management cluster]
    project[Project control plane]
    manager[Connect controller manager]
    reconcilers[Class and project reconcilers]
    gateway[Connect Gateway service]
    vpc[NSO Network]

    mgmt -->|Project discovery and ConnectorClass| manager
    manager --> reconcilers
    reconcilers -->|Connect resources and status| project
    reconcilers -->|Gateway assignment and grants| gateway
    gateway -->|Isolated network attachment| vpc
```

## Reconciler Set

### ConnectorClass

Validates the platform-supported transport and capabilities. The current API
permits `masque-v1` and named TCP, UDP, or IP capabilities. Enrollment requires
exactly one Ready class that advertises `masque-v1`.

### Connector

Validates the immutable 32-byte hex iroh public key and the distinct immutable
RSA authentication public key, then resolves a class that advertises both
`masque-v1` and `connector-authentication`. It provisions a platform-owned Milo
service account and registered public key, creates an exact-Connector-UID
authorization binding in the consumer project, and publishes the provider
identity references in status. It also creates a deterministic 30-second Lease
and publishes Accepted and Ready conditions. Ready depends on identity
provisioning and Lease renewal by the enrolled agent.

The provider fields have intentionally separate meanings: `clientID` is the
OAuth client ID and JWT issuer/subject, `clientEmail` is the service-account
email, and `authProviderKeyID` is the JWT key ID. The service-account UID is an
authorization subject identifier, not an OAuth client ID.

### ConnectorAdvertisement

Requires a Ready Connector and valid TCP/UDP ports. It represents discovery
metadata; the controller never opens the local service or proxies its bytes.

### ConnectGateway

Resolves a ready project-installed `ConnectGatewayClass` and validates routes,
relay policy, network, and placement requirements. Its target contract assigns
the logical gateway to compatible shared or dedicated gateway capacity and
publishes the endpoint, lifecycle phase, idle time, and readiness status. A
`ConnectGateway` does not imply a dedicated runtime instance.

### ConnectNetworkBinding

Validates same-project Connector and gateway references, derives deterministic
client/gateway IPv6 `/128`s, contributes an exact peer grant, and reports the
endpoint, addresses, routes, and relays consumed by the daemon. Ready requires
the assigned gateway service to have the grant applied.

## Gateway Service Assignment

The controller reconciles a logical gateway assignment with:

- an endpoint identity and relay reachability;
- an isolated attachment to the requested VPC Network;
- exact project and Connector grant configuration;
- shared multi-tenant placement by default, or dedicated single-tenant
  placement when requested and available; and
- an applied configuration generation used for readiness.

The runtime topology behind that assignment is not part of the Connect API
contract. The platform can implement an assignment with shared processes,
dedicated capacity, or a different scheduler as long as the endpoint, network
isolation, grants, and readiness contract remain intact. The Network reference
remains a name-only cross-service reference.

## Binding Reconciliation Flow

```mermaid
sequenceDiagram
    participant Daemon
    participant API as Project API
    participant Controller
    participant Gateway

    Daemon->>API: create ConnectNetworkBinding
    Controller->>API: read Connector and ConnectGateway
    Controller->>Controller: derive addresses and routes
    Controller->>Gateway: reconcile assignment and grants
    Gateway-->>Controller: endpoint ready and config applied
    Controller->>API: publish endpoint and verify applied grant
    Controller->>API: mark binding Ready with status
    Daemon->>Gateway: authenticated CONNECT-IP
```

## Deployment

The manager uses leader election. Metrics bind to port 8080 and probes to 8081.
The container runs as UID/GID 65532 with a read-only root filesystem, Runtime
Default seccomp profile, and no Linux capabilities. Its credentials must read
Milo discovery resources and reconcile the defined resources in project
control planes.

## Failure Semantics

- Invalid specs produce conditions rather than partial child resources.
- Identity provisioning remains unready until the service account exposes its
  client ID and email and the registered key exposes its provider key ID.
- The controller preserves connector-owned `status.transport` while writing
  authentication and readiness status.
- Lease expiry removes Connector readiness without forcing a disruptive gateway
  restart for every peer.
- Route count, grant convergence, and gateway-service readiness are explicit
  binding failure reasons.
- Gateway Ready means the assigned endpoint and network attachment are
  available, not that an end-to-end destination probe succeeded.
- Deleting a binding removes its grant on the next reconciliation.
- Connector deletion remains pending until its UID-scoped binding, registered
  key, and service account have each been observed absent.

## Preview Compatibility

This is a clean `v1alpha1` contract. Connectors created with the previous flat
transport fields or a separate authentication-enrollment resource must be
deleted and recreated. There are no deprecated field aliases or automatic
conversion paths. A future key-rotation flow requires an explicit versioned
contract rather than mutation of either current public key.

## External References

- [Connect Gateway Architecture](./gateway-architecture.md)
- [Managed VPC Attachment](../architecture/managed-vpc-attachment.md)
- [Resource Model](../architecture/resource-model.md)
- [Connect API and controller guide](../../connect-controller/README.md)
