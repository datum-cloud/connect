# Datum Connect product overview

Datum Connect gives a device an authenticated identity inside a Datum project,
then uses that identity to connect applications, people, and project networks.
It is designed for reaching private resources without opening inbound firewall
ports, while keeping public exposure an explicit choice.

Connect is currently a preview. Use it for evaluation and controlled staging
workloads, and review the limitations below before relying on it for a critical
path.

## What you can do

- **Share an application with project members.** Use `serve` to share it
  privately, then use `dial` to reach it through a local loopback port. See
  [Private services](../guides/private-services.md).
- **Put a local web application on a public hostname.** Publish the TCP service
  with `serve --public` through a compatible platform gateway. See
  [Public services](../guides/public-services.md).
- **Reach private addresses in a project VPC.** Join the managed network through
  its Connect gateway. See
  [Project network access](../guides/project-network-access.md).
- **Give two devices controlled IP connectivity.** Create a direct network with
  explicit protocol and port permissions on both devices. See
  [Direct device networking](../guides/direct-device-networking.md).

These workflows can coexist on one device. For example, a developer can share
a local application with a teammate while also joining a staging VPC.

## Who Connect is for

- **Application developers** can share a development server, database, SSH
  endpoint, or UDP service without publishing it to the internet.
- **Platform teams** can give approved devices access to project networks and
  publish selected web applications through managed gateways.
- **Operators and automation** can run the daemon as a persistent background
  service and inspect machine-readable status with `--output json`.

## Product principles

### Private by default

`serve` creates a private service unless you explicitly pass `--public`.
Private access can be narrowed further with `--allow`. Public publication is a
separate workflow with its own gateway requirements.

### Local applications keep using local addresses

The application being shared can continue listening on `localhost`. A consumer
also connects through a loopback-only local port. Connect carries the traffic
between the two authenticated devices.

### Device identity is durable

The local daemon keeps the device's Connector identity and saved intent across
individual CLI invocations. `down` disconnects the project without forgetting
that identity; `up` resumes saved services and forwards.

### Network access is explicit

Managed network joins install only the approved address and routes. Direct
device networks require both peers to name each other and declare permitted
traffic. The networking helper owns privileged interface changes without
receiving cloud credentials or Connector keys.

## What Connect is not

Connect is not a general-purpose resource-management CLI. Use `datumctl get`
and `datumctl edit` to inspect or change cloud resources. It also does not
automatically configure a routed host's firewall, forwarding, source NAT, or
return routes.

`ping` checks whether another Connector is reachable. It does not test a
specific shared application or an arbitrary VPC address.

## Preview limitations

- Public ingress requires a compatible gateway and control-plane configuration.
- Public services support TCP, not UDP.
- Managed network guidance currently uses IPv6; dual-stack attachments are not
  supported.
- Direct device network attachments are ephemeral.
- Identity rotation and the desktop thin client are unfinished.
- Windows requires credential-file authentication, and its driver and native
  service still require validation on a Windows host.

For operational prerequisites and test boundaries, see the
[headless preview validation guide](../headless-preview.md). For implementation
and trust boundaries, continue to the [architecture overview](../architecture/README.md).
