# Run the local CONNECT-IP prototype

For the opt-in production HTTP/3 CONNECT-UDP listener, certificate provisioning,
static routing, and its fail-closed authorization boundary, see
[`../../docs/masque-interoperability.md`](../../docs/masque-interoperability.md#run-the-production-listener).

## Export OpenTelemetry traces

The daemon and gateway export OpenTelemetry traces only when you configure an
OTLP endpoint. Without an endpoint, they keep writing their normal structured
logs and send no telemetry to a collector.

Set `DATUM_CONNECT_OTEL_ENDPOINT` on both processes to the collector's OTLP/HTTP
base URL. For a local collector, use `http://127.0.0.1:4318`. You can also use
the standard `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` variable with its full traces
URL, or `OTEL_EXPORTER_OTLP_ENDPOINT` with the base URL. Restart each process
after changing the environment.

The client propagates W3C trace context in the CONNECT-IP request. The gateway
continues the same trace, so you can follow setup and session health events on
both sides. The processes export setup, session, and periodic health-snapshot
spans; they do not create a span for each packet. Trace attributes can include
network names, peer identifiers, and connection diagnostics. Send traces only
to a collector you trust, and apply your normal retention and access controls.

The exporter uses HTTP/protobuf and gives each export request a three-second
timeout. Export is batched. A collector outage does not stop packet forwarding;
check the process logs for exporter shutdown or delivery errors.

This guide covers native adapters and low-level local CONNECT-IP tests. For
managed VPC access, run `datumctl connect join NETWORK` against a deployed
`ConnectGateway`; see the [controller guide](../../connect-controller/README.md).
The static `--local-ip-config` example below does not create a
`ConnectNetworkBinding`.

You can attach an enrolled Connector to an explicitly approved IPv4 or IPv6 network
using native Linux, macOS, or Windows adapters. This does not create a production NetworkBinding
or enable VPC attachment against an unmodified deployed gateway.

Use a disposable test host for privileged adapter validation. The Linux container
lab remains the default isolated test. Native macOS and Windows runs create a
real host interface and the explicitly approved routes; they require elevation.
No adapter changes the default route, global forwarding, or firewall settings.

| Platform | Native adapter | Prerequisites |
| --- | --- | --- |
| Linux | Exclusive, nonpersistent TUN | `/dev/net/tun`, `iproute2`, `CAP_NET_ADMIN` |
| macOS | Kernel-assigned utun | Root daemon; built-in `/sbin/ifconfig` and `/sbin/route` |
| Windows | Exclusive Wintun | Administrator or LocalSystem; pinned official Wintun 0.14.1 DLL beside the daemon |

On macOS, `interface_name` is a configuration label. The kernel assigns the actual
`utunN` name. `status --output json` reports both `interface_label` and
`interface_name`, plus `adapter` (`linux_tun`, `macos_utun`, or `windows_wintun`).
Windows and Linux use the requested interface name. Windows refuses an existing
adapter or exact route prefix. The daemon owns only interfaces it creates.
Windows adapter creation runs on a blocking worker so driver setup does not stall
the daemon API. Cancelling a join stops further setup and rolls back owned state
after any in-flight Windows operation returns. Cleanup is not necessarily
instantaneous. macOS keeps its utun open until cancelled configuration processes
have exited, preventing a stale command from affecting a reused interface name.

Start the daemon with `--local-ip-config /private/ip.json`. The configuration must
be a regular private file. Unix requires owner-only permissions and ownership by
the daemon user or root. Windows requires a protected DACL permitting only the
owner, SYSTEM, and Administrators. Symlinks/reparse points are rejected.
A configuration approves exact project/network pairs:

```json
{
  "underlay_address": "172.20.0.2",
  "bindings": [{
    "project": "demo",
    "network": "local-vpc",
    "gateway": "GATEWAY_PUBLIC_KEY",
    "addresses": ["172.20.0.3:4433"],
    "assigned_address": "192.0.2.2/32",
    "routes": ["10.78.0.0/24"],
    "interface_name": "dcip0",
    "mtu": 1280
  }]
}
```

Replace the example key and address with the gateway's actual identity and QUIC
address. Set the required `underlay_address` to this daemon's existing, explicit
IPv4 or IPv6 address on the physical or container network. Every gateway socket
must use the same address family as that underlay address. When you enable this mode,
every project endpoint binds only that address before enrollment. Wildcard binds
can discover TUN addresses and route transport traffic back into the overlay.
The underlay and every gateway address must remain outside every approved route
and assigned IP, including those belonging to other projects. Startup rejects
overlapping configurations. Restart the daemon if its underlay address changes;
this prototype does not migrate endpoints automatically.
Use non-loopback, non-link-local IPv4 or global/ULA IPv6 underlay addresses.
Wildcard, IPv4-mapped IPv6, and multicast addresses are rejected.

Configure the gateway to approve this Connector's existing project key
and advertise the same assigned address, routes, and MTU. The daemon rejects a
different grant before it creates an interface. Default routes and broad
catch-all routes are unsupported. The daemon never adopts an existing interface
or replaces existing routes.

For an IPv6-only lab, set `underlay_address` to an address such as
`2001:db8:10::2`, gateway `addresses` to `["[2001:db8:10::3]:4433"]`,
`assigned_address` to `2001:db8:20::2/128`, and `routes` to
`["2001:db8:30::/64"]`. Replace these documentation addresses with your lab's
configured addresses. Each binding uses one overlay family: IPv4 assignments
require `/32`, IPv6 assignments require `/128`, and all its routes must match.
The overlay family can differ from the underlay family. Use separate bindings
for separate IPv4 and IPv6 overlays. IPv6 overlays support global or ULA prefixes
between `/16` and `/128`, not link-local, multicast, or IPv4-mapped addresses.
IPv6 packets use fixed headers with TCP, UDP, or ICMPv6; extension headers and
fragments are unsupported. You can keep the local control API on IPv4 loopback
when the data-plane underlay and overlay use IPv6 only.

CONNECT-IP carries packets in HTTP/3 QUIC DATAGRAM frames, without a reliable
stream fallback. The approved MTU must remain between 1280 and 1500 bytes. The
transport checks that the current path can carry that entire IP packet after
datagram framing overhead. If the peer does not support datagrams or path capacity
is too small, `join` fails before creating a local interface. Ask the gateway
operator to check DATAGRAM support and the direct or relay path MTU. Do not lower
the approved MTU below 1280 to hide an unsuitable path.

After normal project enrollment, use the flat CLI:

```sh
datumctl connect up --project demo --credentials-file /private/credentials.json
datumctl connect join local-vpc --project demo
datumctl connect status --project demo
datumctl connect leave local-vpc --project demo
```

Successful `join` output identifies the assigned address and interface, lists
the routes, marks the attachment as an ephemeral native prototype, and provides
the matching `leave` command. Repeating `join` for a running attachment is
idempotent. Repeating `leave` is safe. Use `status --output json` for packet and
drop counters and the last attachment error.
`packets_sent` and `packets_received` count local adapter delivery. The nested
`transport` object reports wire-layer packet counters, policy drops, and protocol
errors. Gateway attachments mirror transport `packets_dropped` and
`protocol_errors` at the top level; do not add the two views together. Peer
attachments add `acl_drops` to the top-level dropped-packet count.
`delivery_mode` is `quic_datagram`. `effective_datagram_ip_capacity` reports the
maximum IP payload that fits in one datagram on the observed path, not the outer
link MTU. `mtu_errors` counts capacity failures. `last_transport_error` preserves
the transport failure reason. The nested `transport` object also includes
`datagrams_sent` and `datagrams_received`. Human-readable status shows the delivery
mode, capacity, MTU error count, and latest transport error.

For live packet-path diagnosis, daemon logs emit a `connect_ip_health` snapshot
every 10 seconds with per-session and attachment-total packet counts, packet
bytes in each direction, QUIC datagram counts, transport drops, and the last
packet timestamp in each direction. The daemon emits a final
`connect_ip_attachment_stopped` event with the last session ID, state, reconnect
count, packet totals, and last error. `status --output json` exposes the current
attachment counts as
`local_tun_to_transport_packets` and `transport_to_local_tun_packets`, plus the
same last-packet timestamps.
The gateway emits the matching per-session `connect_ip_health` snapshot with
the same `session_id`, QUIC datagrams received/sent, packets and bytes injected
into/returned from its TUN, and policy-drop counts by reason. Its final
`connect_ip_session_closed` event includes the session duration, close reason,
directional totals, and datagram diagnostics. It also samples the per-session nftables
postrouting rule every 10 seconds, with a 2-second query bound, to report
packets and bytes matched by the VPC egress-NAT rule. Correlate client and
gateway events by `session_id`; use `network`, `gateway`/`peer`, and timestamps
when one side did not receive the session request. If
client-to-gateway counts advance but gateway injection does not, investigate
transport or gateway admission; if injection
advances but NAT does not, investigate gateway forwarding and routes; if NAT
advances but return traffic does not, investigate VPC routing, workload
firewall, or service health; if gateway return advances but client receive does
not, investigate the QUIC path or local adapter. These counters locate the
failing segment; they do not identify which VPC firewall or workload rule
blocked a packet.

Attachments do not persist across daemon restarts. `leave`, `down`, lost
Connector authorization, session failure, and daemon shutdown close the owned
TUN descriptor and remove its interface and routes. Rejected packets increment
drop counters without terminating a healthy session. The normal project
enrollment, token roles, and project scopes still apply. `ping` retains its
Connector-probe meaning; use your operating system's `ping` command for an approved VPC address.

If path capacity shrinks below the approved MTU during a session, the transport
pauses outgoing packets for up to three seconds while iroh probes new paths.
Packets during this interval are dropped and counted; application-level UDP
retries remain necessary. If capacity stays too small, the transport fails closed.
The daemon removes the owned interface and routes, and status
reports the MTU failure. It does not silently fragment packets, reduce your
approved MTU, or switch to reliable packet delivery. Correct the path or matching
endpoint configuration before you run `join` again.

## Install a native privileged daemon

Unprivileged user services support OIDC, TCP, and UDP. For peer CONNECT-IP on
macOS/Linux, use the networking helper below to retain your user daemon and login.
The system-daemon alternative in this section requires credential-file
authentication. Do not pass a user's OIDC session to a root daemon.

Install the executable in a root-owned, non-writable-by-users location before
installing the macOS system service. For example, after building locally:

```sh
sudo install -o root -g wheel -m 755 connect-lib/target/debug/datum-connect-daemon /Library/PrivilegedHelperTools/datum-connect-daemon
sudo datumctl connect daemon install --system \
  --executable /Library/PrivilegedHelperTools/datum-connect-daemon \
  --credentials-file /absolute/credentials.json \
  --local-ip-config /absolute/ip.json
sudo datumctl connect daemon start --system
```

Do not run a user daemon and a system daemon on the same API port. The installer
copies credentials and IP policy into protected service state. It does not enroll
a project. Set the explicit project and system setup token when operating it:

```sh
sudo datumctl connect up --project PROJECT \
  --token-file '/Library/Application Support/Datum Connect/daemon_auth/setup.token'
sudo datumctl connect join NETWORK --project PROJECT \
  --token-file '/Library/Application Support/Datum Connect/daemon_auth/setup.token'
```

On Windows, install the daemon and matching signed `wintun.dll` beneath
`C:\Program Files\Datum Connect`. From an elevated PowerShell terminal:

```powershell
datumctl connect daemon install --system `
  --executable 'C:\Program Files\Datum Connect\datum-connect-daemon.exe' `
  --credentials-file 'C:\private\credentials.json' `
  --local-ip-config 'C:\private\ip.json'
datumctl connect daemon start --system
datumctl connect up --project PROJECT `
  --token-file "$env:ProgramData\Datum\Connect\daemon_auth\setup.token"
datumctl connect join NETWORK --project PROJECT `
  --token-file "$env:ProgramData\Datum\Connect\daemon_auth\setup.token"
```

The native Windows Service Control Manager starts and stops the daemon. Service
stop cancels attachments and closes the owned adapter. Interactive host-session
OIDC remains unsupported on Windows. Use a `datum_service_account` file or a
renewable `connector` refresh-token file. Both refresh in-process without the
interactive login helper. The installer rejects host-session descriptors and
refuses to overwrite an existing service. Keep the
system setup token private. Use scoped daemon API tokens when delegating access.

If the service fails before it can open its protected JSON log, check the
Windows Application event log for source `datum-connect-daemon`. The fallback
records a fixed lifecycle stage and an optional numeric OS status, not tokens,
credential contents, or session metadata. Detailed runtime errors stay in the
protected `daemon.log`. STOP and system SHUTDOWN use the same bounded cleanup
path; actual shutdown timing still depends on Windows service-manager policy.

For a local Windows build, stage the official signed DLL and license beside the
executable with `python scripts/stage-wintun.py --arch amd64 --destination PATH`
(use `arm64` for ARM64). The script verifies the archive digest published by
[Wintun](https://www.wintun.net/). The adapter also verifies a pinned DLL digest
and prevents replacement while loading. It never searches PATH or the working
directory for the driver. Release archives include the matching DLL and license.

## Validate native adapters

The opt-in native tests send real UDP through the OS interface, inject a reply,
check IPv4 and IPv6 packets up to the 1280-byte MTU, and verify interface cleanup.
They create documentation/ULA host routes. Run only on a disposable elevated host:

```sh
cd connect-lib
cargo test -p connect-ip-adapter --test native_tun --no-run
# Run the printed native_tun test executable as Administrator/root:
PATH_TO_TEST_EXECUTABLE --ignored --test-threads=1
```

For Windows tests, stage `wintun.dll` beside the test executable in
`target/debug/deps`, not only beside the daemon. Native platform CI runs these
tests on macOS and Windows. Configuring CI does not mean those jobs have run.

Local verification covers macOS builds/unit tests and the unprivileged rejection
path, a linked Windows GNU amd64 daemon, Windows CLI subprocess/HTTP-contract
tests under Wine 10, and Linux IPv4/IPv6 adapter packet tests. Privileged
macOS packet tests require administrator access; Windows driver, ACL, and service
runtime tests require a Windows host. No native macOS/Windows cross-machine
CONNECT-IP success is claimed from compilation alone.

The Windows GNU target disables implicit DLL exports in
[the Cargo configuration](../../.cargo/config.toml). Otherwise GNU ld auto-exports
the Rust dependency graph of `iroh-relay`'s unused cdylib and exceeds the PE export
limit. Connect links the Rust library; it does not require `iroh_relay.dll` at
runtime. The release workflow still targets MSVC; that build and native Windows
execution remain unverified locally. Wine does not provide equivalent protected
DACL and reparse-point behavior, so its results do not certify storage security.

To cross-build on a host with Rust's Windows GNU target and the MinGW-w64 C
compiler installed, run from the repository root:

```sh
cd connect-lib
cargo build --locked -p datum-connect-daemon --target x86_64-pc-windows-gnu
```

For prebuilt CLI contract tests, compile `connect-plugin`'s tests for Windows
and set `DATUM_CONNECT_TEST_PLUGIN` to the absolute Windows path of the plugin
executable. Without this variable, the test suite builds a fresh plugin with Go.

### Verify the Windows service

On a disposable Windows host, build the daemon with the pinned Rust toolchain
and build the Go plugin. Run the service smoke test from an elevated PowerShell 7
terminal in the repository root:

```powershell
Push-Location connect-lib
cargo build --locked -p datum-connect-daemon
Pop-Location
Push-Location connect-plugin
go build -o ../target/windows-amd64/datumctl-connect.exe .
Pop-Location
./scripts/windows-service-smoke.ps1 `
  -Plugin (Resolve-Path target/windows-amd64/datumctl-connect.exe) `
  -Daemon (Resolve-Path connect-lib/target/debug/datum-connect-daemon.exe)
```

The test exercises install, start, loopback health, authenticated status,
unauthenticated rejection, stop, restart, private ACLs, and uninstall under the
real Service Control Manager. It uses fake credentials
without calling `up`, so it creates no cloud resources and does not load Wintun.
It refuses an existing Connect service, state directory, staging directory, or
occupied test port. It removes only test-owned artifacts after confirming service
removal. If cleanup fails, it preserves state and the executable for diagnosis.
Run the separate native packet tests above to validate the driver and IP routing.

## Set up peer IP from the CLI

Use matching new plugin, daemon, and helper builds on both devices. Published
`v1.0.0-preview.3` does not contain this workflow. No JSON configuration or
`--local-ip-config` is needed for guided setup. Your daemon must run as your
ordinary user on macOS or Linux.

```sh
# On Alice's device:
datumctl connect join friend --peer bob-mac --allow-tcp 8080 --allow-ping
# On Bob's device:
datumctl connect join friend --peer alice-mac --allow-tcp 8080 --allow-ping
```

Use the same attachment name and project. The command guides enrollment if
needed, pins the discovered Connector key, and generates matching IPv6 host
addresses. `--allow-tcp`, `--allow-udp`, and `--allow-ping` permit the selected
traffic in both directions; both peers must grant it. All other traffic stays
denied. Subnet routes and transit routing are not supported.

On first use, review the peer key, host addresses, and packet rules. Approving
the prompt lets the CLI download the helper from its exact release, verify the
archive checksum, and invoke a short-lived installer through `sudo`. The installer
copies the helper into immutable, root-owned, content-addressed storage. It
checks the digest again before execution. The persistent helper receives only
administrator-approved host pairs, never cloud credentials or Connector keys.
The approved local user's processes share those host-pair privileges; the user
daemon separately enforces the displayed packet rules.

For local builds, pass `--helper-executable` with the absolute path to
`connect-lib/target/debug/datum-connect-network-helper`. Development builds do
not download an unrelated release. Build with `task build`, install the new
plugin with `task install:go`, and use the matching daemon executable. Updating
an existing user daemon remains explicit; preserve its existing repository and
service options. Do not leave an operator-managed `--local-ip-config` override
enabled when switching to guided setup.

After initial setup:

```sh
datumctl connect join friend
datumctl connect status
datumctl connect doctor
datumctl connect leave friend
```

Status shows the overlay addresses, active connections, packet counters, and
helper readiness. Use OS `ping` or an IPv6-capable application against the peer's
overlay address. `doctor` performs read-only checks; helper readiness does not
prove end-to-end peer reachability. `leave`, `down`, or a daemon restart removes
the live interface. Saved peer configuration remains available for explicit
rejoin. Retrying setup cannot silently change an existing pinned peer or its
rules; use a new attachment name for a different grant.

Adding another approved host pair reloads the root-owned approval file for new
requests without restarting active interfaces. A binary upgrade requires
`join friend --upgrade-helper` and explicit confirmation. It restarts only the
networking helper, disconnecting active IP attachments, not your daemon's normal
TCP/UDP services or OIDC session. Failed activation attempts restore the previous
helper service where possible and report failures; existing root approval files
and old binaries remain for recovery. Manually managed helper installations are
never silently replaced.

Scripts, JSON/YAML output, custom daemon URLs, and scoped tokens never trigger
elevation. An administrator must complete setup locally first. API clients with
the setup role can prepare an attachment with `POST /v1/networks/prepare`, inspect
its single-attachment approval plan with `GET /v1/networks/NAME/setup`, and then
use the normal join endpoint. Preparing a plan does not grant OS privileges or
open an interface. The daemon exposes helper health under `networking` in status.
It chooses and binds a physical underlay before creating overlays; after a
physical network change, reconnect with `up` to select a new source address.

Native macOS service installation, administrator prompting, and a real two-Mac
internet test still need validation. The automated API and CLI fixtures do not
claim to exercise OS authorization or production cloud membership.

## Configure the networking helper manually

The helper owns only administrator-approved interfaces and exact peer host routes.
Your existing user daemon retains its OIDC session, Connector keys, authorization,
iroh endpoint, and packet policy. The helper receives neither credentials nor keys.
This feature requires matching newly built plugin, daemon, and helper binaries;
the published `v1.0.0-preview.3` archives do not include it.

This remains a manual prototype. On each Mac, choose a free, matching host pair,
exchange Connector public keys from `connect status --output json`, and identify
your local physical IP and user ID (`id -u`). These examples use documentation
addresses; check for conflicts with your existing VPNs and routes first.

Create `helper-approvals.json`, replacing `501` with your user ID:

```json
{
  "allowed_uid": 501,
  "approvals": [{
    "interface_name": "dcpeer",
    "assigned_address": "192.0.2.2/32",
    "peer_address": "192.0.2.3/32",
    "mtu": 1280
  }]
}
```

Create a private `peer-ip.json` for your user daemon. Replace the physical IP,
remote key, and socket UID. On the other device, reverse the two overlay addresses
and use your Connector's public key. Both sides must approve the desired traffic:

```json
{
  "underlay_address": "192.168.1.10",
  "network_helper": "/Library/PrivilegedHelperTools/datum-connect-network-501/helper.sock",
  "peer_bindings": [{
    "project": "datum-cloud",
    "network": "friend",
    "peer": "REMOTE_CONNECTOR_PUBLIC_KEY",
    "discover": true,
    "assigned_address": "192.0.2.2/32",
    "peer_address": "192.0.2.3/32",
    "interface_name": "dcpeer",
    "mtu": 1280,
    "allow_inbound": [{"protocol": "icmp_echo"}, {"protocol": "tcp", "ports": [8080]}],
    "allow_outbound": [{"protocol": "icmp_echo"}, {"protocol": "tcp", "ports": [8080]}]
  }]
}
```

`discover: true` resolves the pinned public key and its direct/relay addresses.
It excludes overlay addresses from direct candidates, refreshes discovery on
connection attempts, and rechecks peer authorization every 30 seconds. Discovery
does not grant traffic access: the explicit rules still apply. The helper accepts
requests from the approved local UID, not a particular signed application; treat
that user's processes as sharing the approved host-pair network privilege.

Build with `task build`, then run `task install:go` to install the matching plugin.
This does not replace or restart your installed daemon. Stage the helper as a
root-owned executable, then install
its service. Invoke the built plugin directly under sudo to avoid changing root's
datumctl login or plugin registry:

```sh
chmod 600 helper-approvals.json peer-ip.json
sudo install -o root -g wheel -m 755 connect-lib/target/debug/datum-connect-network-helper /Library/PrivilegedHelperTools/datum-connect-network-helper
sudo "$PWD/connect-plugin/datumctl-connect" daemon helper install \
  --uid "$(id -u)" --config "$PWD/helper-approvals.json" \
  --executable /Library/PrivilegedHelperTools/datum-connect-network-helper
```

Do not replace a helper executable used by another installation. Installation
refuses an existing service or state directory rather than overwriting approvals.
The service copies approvals into root-owned private state. Its Unix socket checks
the client's UID, and the user daemon checks that the server runs as root. The
protocol accepts only exact approved interface settings and bounded IP packets.
Helper crash or IPC disconnect removes owned interfaces and routes.

Next, update the user daemon's service configuration. This interrupts existing
tunnels briefly but preserves the standard user's saved identity and login.
Use the matching new daemon at a persistent absolute path. Preserve any custom
state paths, service ports, and existing IP approvals instead of using these defaults:

```sh
datumctl connect daemon stop
datumctl connect daemon uninstall
datumctl connect daemon install --executable "$PWD/connect-lib/target/debug/datum-connect-daemon" --local-ip-config "$PWD/peer-ip.json"
datumctl connect daemon start
datumctl connect up --project datum-cloud
datumctl connect join friend --project datum-cloud
```

Run `join friend` on both Macs. Once status reports `connected`, use OS `ping`
against the other overlay address, or start an HTTP server listening on that
address/`0.0.0.0` at port 8080 and open `http://PEER_IP:8080`. You do not use
`serve` or `dial` for this IP test. Use `connect leave friend` on both devices to
remove the attachment. Restarting either daemon requires both sides to rejoin.

Use `connect status --output json` for `network_helper`, `discovery`, packet/drop
counters, connection attempts, and MTU failures. Helper service status is
`connect daemon helper status --uid UID`; `stop`, `start`, and `uninstall` require
administrator privileges. Logs live under the helper's state directory as
`datum-connect-network-helper-UID.err`. Uninstall preserves approval files.
Windows continues to require its existing system-daemon path.

## Attach two approved peers directly

You can approve one remote Connector per binding without a gateway. This local
prototype uses static operator approval, not dynamic cloud network membership.
Both devices still require normal project enrollment and daemon authorization.
They use their existing project Connector keys and the same transport endpoints
as TCP and UDP services. The lower public key initiates the IP session, so either
device can run `join` first.

Use optional `peer_bindings` alongside or instead of gateway `bindings`:

```json
{
  "underlay_address": "172.20.0.2",
  "underlay_port": 7777,
  "peer_bindings": [{
    "project": "demo",
    "network": "peer-net",
    "peer": "REMOTE_CONNECTOR_PUBLIC_KEY",
    "addresses": ["172.20.0.3:7777"],
    "assigned_address": "192.0.2.2/32",
    "peer_address": "192.0.2.3/32",
    "interface_name": "dcp0",
    "mtu": 1280,
    "allow_inbound": [{"protocol": "tcp", "ports": [22]}],
    "allow_outbound": [{"protocol": "icmp_echo"}]
  }]
}
```

Configure the other device with the addresses and identities reversed. Its
inbound rules must approve traffic that this device initiates, and conversely.
For the example, approve inbound ICMP echo on the other device and outbound TCP
port 22 there. Empty or omitted rules deny all new flows in that direction.
TCP and UDP rules require explicit nonzero destination ports. ICMP echo rules
have no ports. Stateful replies need no separate ephemeral-port rule. Flow state
belongs to one authenticated peer session and has a 1,024-flow cap. New flows
are denied at capacity. Idle expiration is 30 seconds for a pending TCP handshake,
24 hours for established TCP, 60 seconds for UDP, and 10 seconds for an ICMP echo
request. Expired TCP sessions need a new connection. Leave, session failure, and
authorization loss clear all flow state.
After both directions send TCP FIN, the record expires after 30 idle seconds;
late ACKs and FIN retries still pass during that window. A half-closed connection
retains the normal established timeout so the other side can finish its response.

Host-mode peer bindings install only the exact remote `/32` or `/128` route.
For subnet access, set `routes` on the client and exactly matching
`advertise_routes` on the router. Both sides explicitly approve destination
ports. The client installs the subnet routes; the router installs only the
client host route. The router operator separately configures IP forwarding,
firewall rules, and SNAT or a VPC return route. Connect does not change those
global settings. Only the client's assigned host address can initiate traffic;
this does not enable arbitrary site-to-site transit. Replies are tracked by
source/destination address, protocol, and ports within the authenticated session.
Bindings reject self-peer keys and addresses that overlap another
binding's assigned addresses or installed routes. Both host addresses must use the same
family. The underlay family can differ. A fixed `underlay_port` supports one
project per daemon; omit it or use zero for ephemeral transport ports. For a
static lab, configure the approved fixed port on each device before restarting
the daemon. Restart preserves the enrolled Connector key, not IP attachments.

Run `datumctl connect join peer-net --project demo` on both devices. The initial
result may be `waiting_for_peer`: the local interface and approval are active, but no
peer session is connected. The initiator retries while it waits. Status exposes
`connected`, `state`, `connection_attempts`, `last_connect_error`, and `acl_drops`,
alongside datagram diagnostics. `running` means the local attachment task exists;
it does not prove peer connectivity. Connection errors do not grant access.
`acl_drops_by_reason` distinguishes malformed packets, address or port policy,
untracked replies, and flow-table exhaustion. `tracked_flows` reports retained
records; expired records are removed when the next valid host-pair packet is
checked. Debug logs include direction, peer identity, network, and denial reason,
never packet payloads. Top-level packet counters report adapter delivery; nested
transport counters report wire delivery, which can precede an inbound ACL drop.

Run `datumctl connect leave peer-net --project demo` to revoke the local listener
grant, close the session, and remove the owned interface and route. The remote
device also closes its attachment when that session ends. Run `join` again on
both devices after either leaves. `down`, daemon shutdown, and lost Connector
authorization perform the same local cleanup. No peer attachment intent
persists across daemon restarts.

## Test direct peers locally

From the Connect checkout, build and run the Linux lab with privileged helpers
and unprivileged OIDC daemons. Enrollment waits for a reachable relay, so this
command explicitly allows container egress to Datum staging:

```sh
python3 scripts/connect-peer-ip-local.py --docker-context colima-kata \
  --helper --oidc --discover \
  --relay-urls https://iroh-relay.us-central-1.datum-staging.net \
  --build --datumctl-source /absolute/path/to/datumctl \
  --binaries target/helper-ip-linux-bin --keep
```

For subsequent runs, reuse the built binaries:

```sh
python3 scripts/connect-peer-ip-local.py --helper --oidc --discover \
  --relay-urls https://iroh-relay.us-central-1.datum-staging.net \
  --binaries target/helper-ip-linux-bin
```

Add `--relay-only` to block discovered direct peer addresses inside the test
containers and assert that every CONNECT-IP session uses the relay. This does
not modify your host firewall or routes.

Add `--ipv6-overlay` for IPv6 packets over an IPv4 underlay. `--ipv6` instead
requires an IPv6-reachable relay and IPv6 egress. The helper mode runs daemons as
UID 1000 with no effective capabilities and keeps root helpers separate. `--oidc`
uses isolated fake login sessions, never your real credentials. The CLI, helpers,
OS interfaces, iroh transport, and relay enrollment are real. This is still two
containers, not two internet-connected Macs. Build the helper alongside the daemon;
`--build --helper --datumctl-source PATH` includes it automatically.

Replace the datumctl source path on another machine. Keep the sibling
`iroh-gateway` checkout for the shared Linux build helper and test image. The
peer test does not launch a gateway. It uses two daemons in two containers on one
Linux VM. OAuth and the Cloud API are simulated; iroh, HTTP/3, QUIC DATAGRAM, TUN
interfaces, packet filtering, and CLI dispatch are real. No host routes, installed
services, or deployed resources change. Omit `--ipv6` to test IPv4. In IPv6 mode,
only loopback retains IPv4 for local control APIs; all inter-container traffic is
IPv6. Omit `--build` and `--datumctl-source` on subsequent runs with unchanged code.

The suite checks bidirectional ping, HTTP/TCP, UDP, full-MTU packets, independent
inbound/outbound denial, address spoofing, exact-host routes, leave/rejoin,
restart, policy removal, and Cloud authorization loss. Denied ports have real
listeners. Artifact files retain CLI output, status, route/interface snapshots,
and credential-redacted process logs. It is not WAN, relay, or two-VM certification.

Use the printed manifest path to open either device's authenticated shell:

```sh
python3 scripts/connect-peer-ip-local.py --shell target/RUN/lab.json --side client
# In the container:
datumctl connect status
datumctl connect leave peer-net
datumctl connect join peer-net
```

Use `--side peer` for the second device. After a leave, rejoin both devices. Use
the peer address printed by the harness with `ping` and HTTP port `8080`; bracket
IPv6 addresses in URLs. Each container also runs live, intentionally denied test
ports, so keep this lab isolated.

To remove only the lab's labeled disposable containers and network:

```sh
python3 scripts/connect-peer-ip-local.py --cleanup target/RUN/lab.json
```

Diagnostics and build caches remain. Existing VPC labs are not affected.
