# Datum Connect

Use `datumctl connect` to share a local service or join a Connect VPC. The CLI
guides interactive setup and sends requests to a persistent local daemon. Start
with the [documentation index](docs/README.md) or follow the quickstart below.

This repository builds a preview. Managed VPC attachment uses the Connect API
and controller, which are still a staging prototype. `serve` and `dial` continue
to use the existing service publication APIs. See the
[controller guide](connect-controller/README.md) for the current boundary.

For manual installation, follow the [installation guide](docs/INSTALL.txt).
It covers plugin trust, checksum verification, first use, and upgrades.

## Quickstart

Install and trust the Connect plugin, sign in with `datumctl`, and start your
local app. Then run:

```sh
datumctl connect serve localhost:8080
```

On macOS and Linux, the plugin guides daemon installation, enrollment, and
service sharing. It prints the command another Connector can use to connect.
Use `serve --public` only when you want to publish through an HTTPProxy.

## Command-line interface

The interface is flat. There is no `tunnel` noun or compatibility command tree.

```text
datumctl connect
  up | down | status
  join NETWORK | leave NETWORK | ping CONNECTOR
  serve HOST:PORT [--public] [--hostname H] [--allow CONNECTOR,...]
  unserve HOST:PORT | NAME
  dial CONNECTOR:PORT --bind LOCALPORT
  hangup LOCALPORT
  install (optional; serve guides first-time user setup)
  daemon install | uninstall | start | stop | status
  doctor | health | version
```

Services are private by default. Use `--public` to request an HTTPProxy.
Default private access includes project devices, excluding gateway identities
approved by your Connector's class and aliases of those keys. Use `--allow` to
select specific Connectors. Explicitly allowing a gateway can expose your
service through that gateway's ingress.
Use `--protocol udp` with `serve` and `dial` for UDP; TCP is the default.
Use `--project PROJECT` to select a project or use your `datumctl` context.
Use `datumctl get` and `datumctl edit` to inspect and edit cloud resources.
Connect does not provide another general-purpose resource-management CLI.

```sh
datumctl connect serve localhost:8080
datumctl connect serve localhost:3000 --public
datumctl connect serve localhost:22 --allow TEAMMATE_CONNECTOR
datumctl connect dial SERVER_CONNECTOR:22 --bind 2222
datumctl connect status
```

On macOS and Linux, once you set up the plugin, start with `serve` in an
interactive user terminal. You do not need a separate install or up command.
Connect offers to download the daemon from the plugin's exact GitHub release,
verifies the archive against that release's `checksums.txt`, installs the per-user
background service, starts it, uses `datumctl`
for login and project selection, and asks before first enrollment. It then
shares your application and prints a peer connection command. `up` provides the
same guided setup without sharing an application. If you previously ran `down`,
`serve` asks before restoring the project's saved services and forwards.

Downloads support macOS/Linux on arm64 and amd64. They require a published
release with the matching `datum-connectd` archive and checksums. Release
builds report the same version as the plugin. Development builds never download
an unrelated release. For a local build or offline setup, run
`datumctl connect install --executable /absolute/path/to/datum-connectd` once,
then run `serve`. This optional setup command does not enroll a device.
When the plugin and daemon releases differ, `join`, `up`, `serve`, and
`install` upgrade the standard macOS/Linux user service before continuing. The
upgrade verifies readiness and restores the previous service definition if the
new daemon does not start. It briefly interrupts active tunnels. The checksum
protects archive integrity over HTTPS; it is not a publisher signature.

New devices use a hostname-derived Connector resource name. Use `up --name NAME`
to choose a different unique name or recover from a name collision. Existing
Connector names and keys remain unchanged. Names resolve within the project;
new explicit allowlists and dials pin the resolved public key, so reusing a
device name cannot redirect an existing grant. To retarget a saved service or
forward, remove it and recreate it explicitly.

Guided setup never runs for scripts, JSON/YAML output, explicit daemon tokens,
custom daemon URLs, Windows, or root. Those paths retain explicit daemon setup
and `up`. No command silently grants automation access to the setup token.
The platform's MASQUE ConnectorClass requirement still applies.

Sessions pinned to `https://api.staging.env.datum.net` use Datum's staging relays:
`https://iroh-relay.us-central-1.datum-staging.net` and
`https://iroh-relay.us-east-1.datum-staging.net`. Other API environments retain
iroh's preset relays. The daemon accepts `--relay-urls URL,URL` or
`DATUM_CONNECT_RELAY_URLS` to override this selection. Set environment overrides
on the daemon service, not just the shell running the plugin. Invalid overrides
fail explicitly; they never fall back to another relay network.

Enrollment waits up to 15 seconds for a relay connection before publishing its
address. Logs report `relay_configuration`, `relay_ready`, and
`relay_startup_timeout`. Status conflicts retry with fresh resource versions and
ownership checks. API validation errors identify the rejected resource and field
without printing rejected values or credentials.

This branch is a preview, not a production release. Public ingress requires a
gateway and control plane configured for the matching transport profile.
Interactive enrollment uses your current `datumctl` login session. The daemon
pins that session and calls `datumctl auth get-token` to refresh authorization.
It stores the session reference, not your access or refresh tokens. Your
session retains your user permissions; it is not a per-Connector credential.
Use `up --credentials-file /absolute/credentials.json` for service-account
deployment. Use `up --auth oidc` to explicitly replace stored authorization with
the current host session, or `up --auth stored` to reuse stored authorization.

The native [CONNECT-IP prototype](connect-lib/daemon/README.md) supports
`join` and `leave` with explicit local approvals and QUIC DATAGRAM packet delivery.
Each attachment supports an IPv4 or IPv6 overlay, over an independently selected
IPv4 or IPv6 underlay. Dual-stack attachments and IPv6 extension headers remain
unsupported.
Static `peer_bindings` also support direct daemon-to-daemon CONNECT-IP, using the
same Connector key and endpoint. Each binding approves one peer host and explicit
inbound/outbound TCP ports, UDP ports, or ICMP echo. `join NETWORK` activates it;
membership alone grants no traffic access. Explicit subnet attachments use
`--routes` on the client and matching `--advertise-routes` on the router, with
approved destination ports. Guided setup currently uses IPv6. The router
operator configures forwarding, firewall, and source NAT or return routes
separately; Connect never enables them globally. The client still has one
approved source address, so this is not arbitrary site-to-site transit.
Run `scripts/connect-peer-ip-local.py --help`
for the isolated two-daemon test harness.
The `connect-controller` module defines project `ConnectGateway` and
`ConnectNetworkBinding` resources and reconciles each gateway into a Compute
Workload. Managed VPC joins use these Connect resources. Service publication
and peer discovery use Connect-owned Connector and ConnectorAdvertisement
resources; only explicit public ingress still creates an NSO-owned HTTPProxy.
The VPC controller is a staging prototype; validate the gateway-to-instance
packet path on each native OS.
Gateway operators can explicitly enable `spec.peerRouting` to advertise the
assigned `/128` addresses of other ready bindings. The gateway then forwards
device traffic directly between authenticated sessions; this is disabled by
default and does not turn the VPC into a general transit network.
Identity rotation and the desktop thin client also remain unfinished.
On macOS/Linux, first-time direct-peer setup no longer requires JSON files:

```sh
# On your device:
datumctl connect join friend --peer THEIR_CONNECTOR --allow-tcp 8080 --allow-ping
# On their device (use the same network name):
datumctl connect join friend --peer YOUR_CONNECTOR --allow-tcp 8080 --allow-ping
```

The daemon pins each peer's key, derives matching IPv6 host addresses, and saves
the explicit packet rules. Interactive `join` offers administrator-approved
installation of the separate networking helper. Later, use `join friend` to
reuse the saved configuration. Direct peer attachments remain ephemeral. A
successful managed VPC join persists attachment intent and automatically
recreates its CONNECT-IP session when the daemon or project resumes. On the
first managed VPC join, the administrator approves a root-owned, client-only
networking policy for the user. Later managed joins within its IPv6 ULA address
and route ranges, route-width and MTU limits, ephemeral interface behavior, and
active-attachment limits do not prompt. Plans outside that policy fail closed.
Direct peers and route advertisement continue to require exact approvals. The
helper receives typed plans over local IPC, never cloud credentials, URLs,
commands, or arbitrary interface operations. `connect doctor` checks helper
readiness without opening an interface.
`ping`
currently probes a Connector, not an arbitrary VPC address. Native adapters use
Linux TUN, macOS utun, and Windows Wintun. On macOS/Linux, the optional
`datum-connect-network-helper` owns approved peer interfaces while your daemon
keeps its user identity and OIDC session. `daemon helper` is the advanced
troubleshooting surface; see the
[helper setup](connect-lib/daemon/README.md#set-up-peer-ip-from-the-cli).
Peer bindings with `discover: true` resolve pinned Connector keys and their
relay addresses through the project API. Administrator-approved host pairs and
daemon traffic rules remain explicit. Windows uses protected file ACLs and a native system service; it requires
credential-file authentication, not an interactive OIDC session. The Windows
driver and native service still require validation on a Windows host.

Read the [validation guide](docs/headless-preview.md) for enrollment, native
services, token scopes, diagnostics, platform requirements, and test limits.

## Architecture

Start with the [architecture documentation](docs/architecture/README.md) for
system context, end-to-end flows, resource ownership, security boundaries, and
component internals.

| Component | Responsibility |
| --- | --- |
| `connect-plugin/commands` | Flat CLI commands and daemon HTTP requests |
| `connect-plugin/internal/daemonservice` | Native service installation and lifecycle |
| `connect-controller` | Connect APIs, project reconciliation, and managed gateway Workloads |
| `connect-lib/daemon` | Loopback API, authorization, durable intent, reconciliation, and diagnostics |
| `connect-lib/transport` | iroh 1.0, HTTP/3 CONNECT, CONNECT-UDP, local CONNECT-IP, and peer access policy |
| `connect-lib/network-helper` | Separate privileged service executable; no cloud credentials or Connector keys |
| `connect-lib/ip-adapter` | Native interfaces, authenticated helper IPC, and exact host-route enforcement |
| `connect-lib/lib/src/successor` | Host-session or in-process file credentials and Connector-owned control-plane resources |
| `connect-lib/masque-interop-lab` | Reusable standards-facing MASQUE edge plus interoperability lab binary |
| Connect Gateway | Managed CONNECT-IP termination and approved VPC forwarding |

The Rust workspace retains historical library code and the `connect-lib/bin`
development harness. The CLI does not invoke that harness. Product builds and
release archives include `datumctl-connect`, `datum-connectd`, and the
networking helper on macOS/Linux. The helper is not installed or elevated for
ordinary `serve` and `dial` commands.

## Build and validate

Use the versions in `connect-plugin/go.mod` and
`connect-lib/rust-toolchain.toml`. The canonical tasks are:

```sh
task build
task test
task test:e2e
task install
```

`task test:e2e` drives real daemon processes and iroh TCP/UDP traffic with a
simulated OAuth endpoint and control plane. Its OIDC mode also tests session
pinning, credential renewal, and logout with an isolated fake credential helper.
It creates no live Datum resources or changes to your real login.
`task install` installs the CLI and daemon locally; it does not enroll a project.

You can use `nix develop` for the development shell. `nix build` targets the
daemon. Native packaging and pinned-toolchain verification still require CI.

## Breaking migration

There is no deprecation window on this branch. Replace old `tunnel` commands
with `serve`, `dial`, `status`, and the daemon lifecycle commands. Existing
scripts that expect a public URL must explicitly use `serve --public`.
No command silently adopts old keys, resources, credentials, or background
processes. Stop an old installation with its old CLI before replacing it.

Release configuration packages the CLI and daemon together. Numbered preview
releases do not replace the production latest release or declare stable 1.0.0.
