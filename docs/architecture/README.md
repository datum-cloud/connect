# Datum Connect Product Architecture

Datum Connect gives people and workloads a consistent way to reach private
resources without first exposing them to the public internet or manually
assembling a VPN. A Connector is an enrolled device that can publish a local
service, dial a service on another Connector, or join an approved project
network.

The product has one user-facing entry point:

```text
datumctl connect
```

The command-line plugin handles interaction. A persistent local daemon owns
device identity, desired state, listeners, and transport sessions so a service
or connection does not depend on an open terminal.

## Product Outcomes

Connect is designed around three tasks:

| Task | User intent | Result |
| --- | --- | --- |
| Publish | Make a local TCP or UDP service available | Approved Connectors can reach it; public HTTP ingress is separate and explicit |
| Dial | Reach a service published by another Connector | A loopback listener forwards to a pinned remote identity and port |
| Join | Attach this device to an approved project network | Only the assigned address and approved routes are installed locally |

Private is the default. Names help people discover devices, but durable grants
pin cryptographic identities. A reused name cannot silently redirect an
existing service allowlist, dial, or network grant.

See [Product Workflows](product-workflows.md) for the end-to-end behavior.

## System Context

![Connect system context](../diagrams/system-overview.png)

Connect separates coordination from traffic:

- The project control plane stores identity, discovery, and network attachment
  intent.
- The local daemon reconciles that intent and establishes authenticated paths.
- Private application bytes and IP packets travel directly when possible or
  through an encrypted relay-assisted path. They do not traverse the Connect
  controller or project API.
- The Connect Gateway service terminates approved project-network attachments.
  Its runtime placement may be shared or dedicated without changing the client
  contract.

## Product Boundaries

Connect owns:

- Connector enrollment, transport identity, and per-Connector control-plane
  identity lifecycle;
- private service advertisements and identity-pinned access policy;
- local service dials;
- project gateway and device-to-network binding intent;
- the authenticated peer, service, and CONNECT-IP transport;
- narrowly approved native interface and route changes.

Connect integrates with, but does not own:

- Datum login, project selection, and project authorization;
- project VPCs and their routing, firewall, and workload policy;
- optional public HTTP ingress;
- shared QUIC relay infrastructure;
- application authentication inside a published service.

Connect does not enable host-wide forwarding, alter default routes, manage a
host firewall, or turn project membership into unrestricted network access.

## Architectural Principles

### Durable intent, replaceable runtime

The daemon persists user intent before applying it and reconciles durable
services, dials, and managed network attachments after restart. Live listeners,
interfaces, and sessions are disposable runtime state.

### Explicit authority at every boundary

A cloud resource, a transport identity, and a local networking approval each
answer a different question. No one of them is sufficient to establish a
network path by itself.

### Least-privileged local networking

Ordinary service publication and dialing run without elevated privileges. When
native networking is needed, a separate helper can apply only an approved
address, interface, MTU, and route set. It receives no cloud credentials or
Connector private key.

### Project isolation

Identity, discovery, policy, runtime state, and telemetry are partitioned by
project. Shared gateway capacity must preserve those same boundaries. Dedicated
capacity changes placement and failure isolation, not the authorization model.

See [Trust and Ownership](trust-and-ownership.md) for the identities, resources,
and tenant boundaries.

## Deployment Model

![Connect deployment topology](../diagrams/deployment-topology.png)

The short-lived CLI and persistent daemon run on the device. The controller
runs centrally and reconciles project-scoped resources. The platform-managed
Connect Gateway service provides isolated project-network attachments. Relays
assist reachability but do not grant access.

See [Deployment Topology](deployment-topology.md) for process placement and
privilege boundaries.

## Delivery Status

These documents define the contract for a sequence of implementation pull
requests. They intentionally distinguish the initial preview from later work.

| Capability | Initial feature series | Deferred or deployment-dependent |
| --- | --- | --- |
| Connector identity and project enrollment | Target | Identity rotation without replacement |
| Private TCP and UDP publication and dialing | Target | Broader application protocols |
| Explicit public HTTP publication | Compatibility path | Production ingress placement and operations |
| Managed project-network attachment | IPv6 preview target | Dual-stack attachments and general site-to-site transit |
| Direct device networking | Preview target | Implicit trust based on project membership |
| Native networking | macOS and Linux helper; Windows service model | Full validation on every target OS and network environment |
| Gateway capacity | Stable logical contract | Platform choice of shared or dedicated runtime placement |

An implementation PR should document its own supported commands, operational
requirements, and test evidence. Component internals belong with the component
that introduces them rather than in this architecture-first PR.

## Architecture Map

- [Product Workflows](product-workflows.md) — publish, dial, and join; control
  plane versus data plane
- [Trust and Ownership](trust-and-ownership.md) — identities, authorization,
  resource ownership, multi-tenancy, and the privileged helper boundary
- [Deployment Topology](deployment-topology.md) — process placement, gateway
  abstraction, and byte paths
- [Architecture Diagrams](../diagrams/README.md) — diagram sources and rendering
  instructions

## Protocol References

- [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221)
- [CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298)
- [CONNECT-IP](https://www.rfc-editor.org/rfc/rfc9484)
