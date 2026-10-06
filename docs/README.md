# Connect documentation

Use these guides to install, operate, and develop Datum Connect.

## Learn and use Connect

- Start with the [product overview](product/README.md) to understand what
  Connect provides and when to use each connectivity model.
- Read the [core concepts](product/concepts.md) for the vocabulary used by the
  CLI and the rest of these guides.
- Follow [Getting started](guides/getting-started.md) to connect a device and
  share your first private service.

### Common tasks

- [Share a private service](guides/private-services.md)
- [Publish a public HTTP service](guides/public-services.md)
- [Access a managed project network](guides/project-network-access.md)
- [Connect two devices directly](guides/direct-device-networking.md)

### Install and validate

- [Install the preview](INSTALL.txt) on a supported host.
- [Validate the headless preview](headless-preview.md) with the CLI and daemon.
- [Run the staging subnet lab](../scripts/STAGING_SUBNET_LAB.md) to test routed access.

## Understand Connect

- Start with the [architecture overview](architecture/README.md).
- See the [deployment topology](architecture/deployment-topology.md) for the
  process placement across user devices, Milo, project control planes, Compute
  workers, VPCs, and relay infrastructure.

### Components

- [Client device](components/client-device-architecture.md) — CLI, daemon,
  local applications, privilege separation, and platform deployment.
- [Daemon](components/daemon-architecture.md) — loopback API, durable state,
  reconciliation, project runtimes, and transports.
- [Network helper](components/network-helper-architecture.md) — privileged
  approvals, packet IPC, and native adapter ownership.
- [Controller](components/controller-architecture.md) — Milo multicluster
  reconciliation and managed gateway provisioning.
- [Managed gateway](components/gateway-architecture.md) — gateway identity,
  admission, CONNECT-IP termination, TUN forwarding, and VPC integration.

### End-to-End Flows

- [Enrollment and reconciliation](architecture/enrollment-and-reconciliation.md)
- [Service publication and dialing](architecture/service-publication.md)
- [Managed VPC attachment](architecture/managed-vpc-attachment.md)
- [CONNECT-IP data plane](architecture/connect-ip-data-plane.md)

### Cross-Cutting Concerns

- [Identity and authorization](architecture/identity-and-authorization.md)
- [Resource ownership and state](architecture/resource-model.md)
- [Multi-tenancy](architecture/multi-tenancy.md)
- [Observability and diagnostics](architecture/observability.md)

### Implementation Guides

- [Connect API and controller](../connect-controller/README.md) describes project resources and gateway reconciliation.
- [CONNECT-IP daemon guide](../connect-lib/daemon/README.md) describes local adapters, approvals, and packet-path diagnostics.

## Develop and release

- Start with the repository [README](../README.md) for build and test commands.
- See [release notes](releases/) for version-specific changes. Older notes describe the behavior at that release.
