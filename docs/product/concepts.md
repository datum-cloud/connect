# Core concepts

This page explains the terms that appear in the Connect CLI and usage guides.

## Project

A Datum project is the administrative and trust boundary for Connect. Your
current `datumctl` context selects the project unless you pass
`--project PROJECT`.

## Connector

A Connector represents one enrolled device or workload. It has a project-local
name and a cryptographic identity. Commands such as `dial`, `ping`, and
`join --peer` accept a Connector name or public key.

Names make interactive use convenient, but saved permissions and forwards pin
the resolved public key. Reusing a name therefore does not silently redirect an
existing grant.

## Local daemon

The Connect daemon runs in the background on each participating device. It owns
the Connector identity, maintains project connectivity, and remembers services,
forwards, and managed network intent. The `datumctl connect` commands send
requests to this local daemon.

Use `datumctl connect status` for the product view and
`datumctl connect doctor` to check daemon and networking-helper health without
making changes.

## Service

A service maps a Connect endpoint to an application already listening on a
device. The destination passed to `serve` is where that application listens;
it is not a new public listen address.

```sh
datumctl connect serve localhost:8080
```

Services are private by default. A private service can allow project devices or
a narrower list of Connectors. A public service is an explicit TCP publication
through a compatible gateway.

## Local forward

A local forward is a loopback-only port created by `dial`. An application uses
that local port as if the remote service were local, while Connect authenticates
and carries the connection to the serving Connector.

```sh
datumctl connect dial SERVER_CONNECTOR:8080 --bind 18080
```

The service and forward protocols must match. TCP is the default; private
services can also use UDP.

## Network attachment

A network attachment gives the device an approved IP address and routes through
a native interface. It is broader than a service connection: applications can
use permitted network addresses directly instead of opening individual local
forwards.

There are two attachment models:

- A **managed project network** uses a project `ConnectGateway` and a durable
  `ConnectNetworkBinding`. A successful join reconnects after the daemon or
  project resumes.
- A **direct device network** connects two named Connectors. Both peers approve
  each other and declare allowed traffic. This preview attachment is ephemeral.

Use service sharing when you need one known application. Use a network
attachment when software must reach addresses or protocols at the IP layer.

## Connect Gateway

A Connect Gateway is a platform-managed service that terminates authenticated
Connect sessions and forwards approved traffic into a VPC. The deployment model
is designed to use shared multi-tenant capacity by default and, when offered by
the platform, let users request dedicated single-tenant capacity. That placement
choice does not change the client workflow or authorization model.

A Connect Gateway can also provide public HTTP ingress when the platform is
configured for the matching transport profile.

The gateway does not give a device unrestricted transit by default. Its
configured network, binding, routes, and traffic policy determine what is
reachable.

## Saved state and lifecycle

Most service and forward commands describe durable intent:

- `serve` and `dial` remain active after the command exits.
- `unserve` and `hangup` remove the saved configuration.
- `down` disconnects a project and stops its services and forwards without
  erasing the Connector identity.
- `up` connects the project and resumes saved services and forwards.
- `leave` removes a managed network's attachment intent and binding.

Run `datumctl connect status` whenever you need to see the Connector, services,
local forwards, and current connectivity state.
