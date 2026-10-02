# Datum Connect

Use `datumctl connect` to connect your device, expose a local service, and open
ports to other Connectors. A persistent Rust daemon owns networking and state.
The Go CLI sends authenticated requests to its loopback API.

For a preview binary, follow the [manual installation guide](docs/INSTALL.txt).
It covers download verification, PATH discovery, `datumctl plugin trust connect`,
staging login, testing with a friend, and upgrading an existing daemon.

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
  health | version
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
release with the matching daemon archive and checksums. Development builds
never download an unrelated release. For a local build or offline setup, run
`datumctl connect install --executable /absolute/path/to/datum-connect-daemon`
once, then run `serve`. This optional setup command does not enroll a device.
Existing services are not automatically upgraded or replaced. The checksum
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

This branch is a local preview, not a production release. The platform must
implement the new MASQUE contract before you can use the deployed gateway.
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
membership alone grants no traffic access. This prototype does not forward peer
subnets or provide transit routing. Run `scripts/connect-peer-ip-local.py --help`
for the isolated two-daemon test harness.
Production VPC/NetworkBinding integration, least-privilege per-Connector
credentials, identity rotation, and the desktop thin client remain unfinished.
Without local IP configuration, `join` and `leave` fail explicitly. `ping`
currently probes a Connector, not an arbitrary VPC address. Native adapters use
Linux TUN, macOS utun, and Windows Wintun. CONNECT-IP requires a privileged
daemon. Windows uses protected file ACLs and a native system service; it requires
credential-file authentication, not an interactive OIDC session. The Windows
driver and native service still require validation on a Windows host.

Read the [validation guide](docs/headless-preview.md) for enrollment, native
services, token scopes, diagnostics, platform requirements, and test limits.

## Architecture

| Component | Responsibility |
| --- | --- |
| `connect-plugin/commands` | Flat CLI commands and daemon HTTP requests |
| `connect-plugin/internal/daemonservice` | Native service installation and lifecycle |
| `connect-lib/daemon` | Loopback API, authorization, durable intent, reconciliation, and diagnostics |
| `connect-lib/transport` | iroh 1.0, HTTP/3 CONNECT, CONNECT-UDP, local CONNECT-IP, and peer access policy |
| `connect-lib/lib/src/successor` | Host-session or in-process file credentials and Connector-owned control-plane resources |

The Rust workspace retains historical library code and the `connect-lib/bin`
development harness. The CLI does not invoke that harness. Product builds and
release archives include only `datumctl-connect` and `datum-connect-daemon`.

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
