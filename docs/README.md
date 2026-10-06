# Connect documentation

Use these guides to install, operate, and develop Datum Connect.

## Use Connect

- [Install the preview](INSTALL.txt) on a supported host.
- [Validate the headless preview](headless-preview.md) with the CLI and daemon.
- [Run the staging subnet lab](../scripts/STAGING_SUBNET_LAB.md) to test routed access.

## Understand Connect

- Start with the [architecture overview](architecture/README.md).
- See the [deployment topology](architecture/deployment-topology.md) for the
  process placement across user devices, Milo, project control planes, Compute
  workers, VPCs, and relay infrastructure.
- Follow the focused design documents for
  [enrollment and reconciliation](architecture/enrollment-and-reconciliation.md),
  [service publication](architecture/service-publication.md),
  [managed VPC attachment](architecture/managed-vpc-attachment.md), and the
  [CONNECT-IP data plane](architecture/connect-ip-data-plane.md).
- Review cross-cutting design for
  [identity and authorization](architecture/identity-and-authorization.md),
  [resource ownership](architecture/resource-model.md),
  [multi-tenancy](architecture/multi-tenancy.md), and
  [observability](architecture/observability.md).
- Read the component internals for the
  [daemon](components/daemon-architecture.md),
  [controller](components/controller-architecture.md), and
  [network helper](components/network-helper-architecture.md).
- [Connect API and controller](../connect-controller/README.md) describes project resources and gateway reconciliation.
- [CONNECT-IP daemon guide](../connect-lib/daemon/README.md) describes local adapters, approvals, and packet-path diagnostics.

## Develop and release

- Start with the repository [README](../README.md) for build and test commands.
- See [release notes](releases/) for version-specific changes. Older notes describe the behavior at that release.
