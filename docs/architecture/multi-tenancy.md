# Multi-Tenancy

Connect isolates cloud resources, local durable state, transport identity, and
runtime policy by Datum project. A host may participate in several projects,
but membership in one project never grants discovery or traffic in another.

## Project Boundary

The project control plane contains Connectors, advertisements, gateways, and
bindings for that project. Milo's multicluster runtime reconciles each project
with a project-scoped client. The controller does not engage those resources in
the management cluster.

The daemon also maintains an independent project runtime:

- distinct cloud authorization context;
- distinct Connector key and resource identity;
- distinct iroh endpoint and transport policy;
- distinct services, dials, network attachments, and errors;
- project-scoped local daemon tokens.

The CLI must select a project explicitly or inherit it from the current
`datumctl` context. There is no host-global service publication or network join.

## Cluster and Project Resources

`ConnectorClass` is deliberately cluster-scoped because it expresses platform
transport support. Project resources may reference it by name but cannot define
new platform transport capabilities. All other Connect resources are annotated
for the Project parent context.

`ConnectGateway.spec.networkRef` is currently a name-only reference to an
NSO-owned Network in the same project. This is a cross-service contract, not a
cross-project grant.

## Discovery and Default Access

Peer discovery lists Ready Connectors only within the current project. A
private service with no explicit allowlist permits eligible project devices but
excludes gateway identities approved by the Connector class. An explicit
allowlist resolves selected names to keys and can intentionally include a
gateway.

The resolved key is persisted. Moving a name to another device or recreating a
Connector with the same name cannot redirect a saved grant, dial, or peer
binding.

## Gateway Isolation

A ConnectGateway and its bindings live in one project. A binding must reference
a Connector and gateway from that same control plane. Deterministic address
derivation includes project and network context, preventing identical device
keys in different projects from receiving the same binding identity by
accident.

The runtime providing that logical gateway can be shared across tenants. A
shared Connect Gateway must partition endpoint identity, grants, session state,
packet paths, network attachments, and telemetry by project and logical gateway.
No shared-runtime lookup or default may broaden a binding beyond its project,
Connector identity, routes, or network.

Users can request dedicated single-tenant gateway capacity when the platform
offers it. Dedicated placement changes the runtime's resource and failure
isolation, and may carry separate pricing, but uses the same project-scoped
authorization and packet policy. It is not a cross-project access mechanism or
a stronger grant.

Optional peer routing is confined to other Ready bindings on the same gateway.
It does not aggregate routes from another project or turn the gateway into
unrestricted transit.

## Local Delegation

Daemon tokens are bound to a project unless they are the protected setup token.
An operator token may be narrowed further to a single service or dial. Read
responses are filtered to the actor's scopes; project transport, authentication,
and network diagnostics are omitted from resource-scoped views.

The networking helper's approval is local and exact, not tenant-aware cloud
authority. Project and network names participate in the approved binding digest,
while the helper enforces the resulting address, interface, peer, MTU, and
routes.

## Non-Goals

- Organization-wide discovery or implicit organization-to-project access.
- Sharing one Connector key across projects.
- Cross-project VPC routing.
- A global administrator route that bypasses project authorization.
- Hierarchical inheritance of service allowlists.

## Related Documentation

- [Identity and Authorization](./identity-and-authorization.md)
- [Resource Model](./resource-model.md)
- [Managed VPC Attachment](./managed-vpc-attachment.md)
