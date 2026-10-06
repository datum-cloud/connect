# Trust and Ownership

Connect deliberately uses separate identities and approvals for cloud actions,
transport sessions, local daemon access, and native networking. This prevents a
single credential or compromised component from authorizing an entire path.

## Identities

| Identity | Held by | Purpose |
| --- | --- | --- |
| Datum user or service account | User session or protected workload credentials | Authorize project API actions |
| Connector keypair | Local daemon; public key in the project API | Authenticate a device transport endpoint |
| Local daemon token | CLI or approved local automation | Authorize loopback daemon operations |
| Gateway endpoint key | Platform gateway service | Authenticate the selected Connect Gateway |
| Helper IPC credentials | User daemon and privileged helper | Authenticate bounded local networking requests |

Connector and gateway private keys do not belong in project resources. The
networking helper receives neither cloud credentials nor Connector keys.

## Layered Authorization

An end-to-end path requires all applicable layers to agree:

| Layer | Question |
| --- | --- |
| Project authorization | May this principal create or change the requested Connect resource? |
| Resource policy | Does the service, gateway, or binding grant this Connector access? |
| Transport identity | Is the peer the exact key expected by the saved intent? |
| Local daemon scope | May this caller operate this project or resource? |
| Native networking approval | May this process create this exact address, interface, MTU, and route set? |

A binding without an applied gateway grant, a grant presented by the wrong
endpoint, or a valid session without local route approval is insufficient.

## Resource Ownership

The Connect API owns the resources that describe Connector behavior:

| Resource | Scope | Responsibility |
| --- | --- | --- |
| `ConnectorClass` | Platform | Supported transports and platform-approved gateway identities |
| `Connector` | Project | Device public identity, reachability, and readiness |
| `ConnectorAdvertisement` | Project | Services published by one Connector |
| `ConnectGateway` | Project | Logical gateway policy and project-network selection |
| `ConnectNetworkBinding` | Project | One Connector's approved attachment to one gateway |

The initial public-ingress compatibility path may create an HTTP proxy owned by
another Datum API. Ownership metadata must bind it to the creating Connector so
cleanup cannot remove an unrelated resource.

On the device, the daemon owns durable project, service, dial, and managed
attachment intent. The helper owns only the native interfaces and routes that
it creates. Neither component adopts unrelated host networking state.

## Project Isolation

A host can participate in multiple projects, but each project has independent:

- cloud authorization context;
- Connector identity and transport endpoint;
- discovery and policy;
- services, dials, and network attachments;
- local daemon delegation and diagnostics.

Project membership never implies cross-project discovery or traffic. Saved
grants use resolved keys, so recreating a Connector name cannot redirect them.

The gateway runtime may serve more than one tenant only if endpoint identity,
grants, sessions, packet paths, attachments, and telemetry remain partitioned
by project and logical gateway. Dedicated capacity uses the same authorization
contract; it is a placement choice, not a broader grant.

## Privileged Helper Boundary

![Connect client device boundary](../diagrams/client-device.png)

On macOS and Linux, the user daemon retains project credentials and Connector
identity. A separate root-owned helper creates an ephemeral native adapter and
exact host routes. Their authenticated local protocol exchanges typed plans and
framed packets—not shell commands or arbitrary network operations.

An approved plan is bounded by:

- the requesting local user and daemon instance;
- project, network, and peer identity;
- address family and assigned host address;
- interface type, MTU, and lifecycle;
- an exact or policy-bounded route set.

Ordinary service publishing and dialing never need the helper. Connect does not
change the default route, global forwarding, host firewall, or system NAT.
Windows uses a protected native service model because the Unix helper boundary
does not map directly to Windows service and adapter ownership.

## Revocation and Deletion

- Removing a service closes its listener and removes only resources owned by
  that service.
- Removing a network binding removes the effective gateway grant on
  reconciliation.
- Leaving a network closes the local packet path before attempting remote
  cleanup.
- Expired readiness prevents new admission; it does not transfer ownership.
- Replacing an address or route plan requires renewed local approval when the
  existing policy does not cover it.

These rules make a partially failed cleanup restrictive: stale metadata may
need reconciliation, but traffic is not kept open merely because remote
deletion failed.
