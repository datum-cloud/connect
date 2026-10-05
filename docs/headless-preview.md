# Validate the headless Connect preview

Use this guide to build and test the CLI, daemon, and transport. A local build
does not create a release or deploy cloud components. Public ingress requires a
gateway and control plane configured for the matching transport. Managed VPC
joins use the Connect controller; see the [controller guide](../connect-controller/README.md).

## Build and test

Use the Rust toolchain in `connect-lib/rust-toolchain.toml` and the Go version in
`connect-plugin/go.mod`.

```sh
task build
task test
task test:e2e
```

After you install the plugin, you can include the host's real dispatch path:

```sh
python3 scripts/daemon-e2e.py \
  --daemon connect-lib/target/debug/datum-connect-daemon \
  --plugin connect-plugin/datumctl-connect --host "$(command -v datumctl)"
```

The process E2E test starts two real daemons and drives the compiled Go CLI.
Traffic crosses real iroh connections and HTTP/3 before reaching a TCP origin.
The test simulates OAuth and the Kubernetes-style control plane on loopback.
It checks device/project identity isolation, TCP and concurrent UDP clients,
private publication, explicit public intent and asynchronous readiness, token
authorization and revocation, restart recovery, cleanup, and diagnostic redaction. It leaves logs
in a printed temporary directory. It does not certify a live Datum gateway,
NAT traversal, relay fallback, signed packaging, or a VPC.

Test host-session enrollment separately with an isolated fake `datumctl`
credential helper. This mode invokes the plugin directly so your real host
cannot replace the fixture session. It does not read or change your real login.

```sh
python3 scripts/daemon-e2e.py --oidc \
  --daemon connect-lib/target/debug/datum-connect-daemon \
  --plugin connect-plugin/datumctl-connect
```

This mode checks real TCP forwarding, secret-free session descriptors,
short-lived access-token renewal, session pinning across context changes and
daemon restarts, and fail-closed behavior after helper logout. Do not combine
`--oidc` with `--host`.

## Run the CLI

For a manually distributed preview, follow [INSTALL.txt](INSTALL.txt). Each
release archive bundles the CLI and daemon. Put the plugin on PATH, explicitly
trust it with `datumctl plugin trust connect`, then use `datumctl connect serve`.
The instructions use a separate plugin registry so an existing managed plugin
does not shadow the preview. They include a local/offline daemon installation path when the
matching release is not published yet.

### Prepare and publish a preview

The release workflow bundles both binaries, `INSTALL.txt`, and the license for
each platform. It stages releases as drafts and does not
change the production latest-release pointer. Use a unique numbered preview
tag. Replace the example version in the packaging command with that tag. Do not
use the unpublished `v0.1.0-dev` identifier.

Review and commit the intended source changes first. From that clean checkout,
run the tests with the pinned toolchains. Check that your chosen tag is unused.
Then push the reviewed source branch and annotated preview tag to trigger
`.github/workflows/release.yml`. Do not attach local dirty-worktree binaries to
an unrelated source tag. Wait for the complete release workflow before sharing
the download link. A release needs all intended archives, `checksums.txt`, and
the standalone `INSTALL.txt`. Verify the checksums and archive contents, then
publish the draft as a prerelease without marking it latest. Installation
downloads from this exact tag only after publication.

For local evaluation before publication, package a freshly built native daemon:

```sh
bash scripts/package-preview.sh v1.0.0-preview.N \
  /absolute/path/to/datum-connect-daemon /absolute/path/to/new-bundle-directory
```

The script builds the matching-version CLI and packages the supplied daemon.
It refuses an existing output directory. It never pushes, publishes, changes
plugin trust, or installs a service. Share its archive, `checksums.txt`, and
`INSTALL.txt` together. The recipient uses the explicit local daemon installation
step in the instructions until the matching GitHub release is available.

### Start sharing

For an interactive macOS/Linux user, the shortest path is
`datumctl connect serve localhost:8080`. It guides daemon installation/start,
host login/context selection, and device enrollment, then shares the service.
`up` remains available for explicit enrollment and reconnecting. A previous
`down` requires confirmation before `serve` restores saved networking.
Prompts default to no. Cancelling stops further work; an already-confirmed
service installation remains installed. Existing services are never overwritten.

Guided setup is restricted to the default local API with implicit interactive
setup authorization. Explicit tokens, custom URLs, JSON/YAML output, scripts,
root, and Windows retain the manual setup below. A custom cloud environment
requires an explicit `datumctl login` rather than silently using production.
New devices use the hostname as their project-unique resource name; choose
`up --name NAME` on a collision. Existing names are preserved. New named dials
and explicit allowlists persist the resolved public key, not a mutable alias.

After you set up a released plugin, `serve` downloads its matching daemon when
the user service is missing. You do not need to put the daemon on PATH or run
`connect install` first. The downloader uses the exact plugin release tag,
verifies the archive against `checksums.txt` over GitHub HTTPS, and installs only
the daemon into a private versioned directory under the plugin state directory's
`runtime` subdirectory. It rejects unsafe archive paths and links. It never falls
back to the latest release or replaces an existing service. Checksums are not
publisher signatures; release signing and notarization remain separate work.

The automatic download path supports macOS/Linux arm64 and amd64. It requires
published release assets, so an unpublished local build cannot bootstrap from
GitHub. For local testing or offline installation, use a trusted daemon build:

```sh
datumctl connect install --executable /absolute/path/to/datum-connect-daemon
datumctl connect serve localhost:8080
```

`connect install` installs, starts, and checks the default user service without
logging in, enrolling, or sharing anything. It leaves existing services unchanged.
An interrupted setup can leave a `runtime/setup.lock`; remove it only after you
confirm no installer is running. A failed start preserves the installed service
for diagnosis with `daemon status` and `daemon.log` in the daemon state directory.

For explicit system setup, install `datumctl-connect` and `datum-connect-daemon`
together in your PATH or the `~/.datumctl/plugins` directory. The lower-level
`daemon install` discovers the daemon next to the plugin before searching PATH.
Trust your local plugin with
`datumctl plugin trust connect` if the host requests it.

```sh
datumctl connect
datumctl connect daemon install --help
datumctl connect daemon install
datumctl connect daemon start
datumctl connect health
datumctl connect status --project PROJECT
```

Use `daemon install --help` to select a credential file and service scope.
Installation writes service configuration and sends structured logs to
`daemon.log` in the selected service state directory. Configure external log
rotation for that file. Starting the daemon is a separate operation. You can
also run it in a terminal without an OS service:

```sh
datum-connect-daemon --repo /absolute/private/connect-state --port 47780
datumctl connect status --project PROJECT \
  --token-file /absolute/private/connect-state/daemon_auth/setup.token
```

An interactive CLI can load its default local setup token. Automation must
explicitly provide `--token-file` or `DATUM_CONNECT_TOKEN`. Do not give an AI
agent the setup token. Mint a project- or resource-scoped operate token through
`POST /v1/tokens?project=PROJECT` using setup authorization. Use a viewer token
for read-only diagnostics. The API returns the bearer only when you mint it.
The default output shows readable status summaries and service tables.
`--output json` emits the complete daemon response as compact JSON, and
`--output yaml` emits YAML. Use `--verbose` for HTTP status, request IDs, and
request timing when an operation fails.

## Enroll and publish

For interactive use, log in through `datumctl` and enroll with `up`:

```sh
datumctl login
datumctl connect up
```

Connect uses the project in your current `datumctl` context. Add
`--project PROJECT` to override it.

The plugin passes your current host session, API endpoint, and the absolute
`datumctl` executable path to the daemon. The daemon stores that descriptor and
calls `datumctl auth get-token --session SESSION --output client.authentication.k8s.io/v1`
when it needs an access token. The host owns login and token refresh. The daemon
caches the returned access token in memory for at most 30 seconds, subject to
its expiration. It does not persist host access tokens or refresh tokens.

The daemon pins the selected session. Switching your current `datumctl` context
does not change an existing enrollment. Plain `up` reuses stored authorization.
Use `up --auth oidc` to explicitly switch stored authorization to your current
host session, or `up --auth stored` to require the existing configuration.
These modes do not create a new Connector identity. The helper executable path
is canonicalized and pinned. If a host upgrade removes that executable path,
run `up --auth oidc` to register the new path.

The daemon must run as an OS user that can access the selected host session.
Use a user service for interactive login. Root/system daemons reject host-session
enrollment; supply service-account credentials for those deployments.
Logging out or losing access to the
session stops networking when the daemon next checks authorization; this is
not an instantaneous revocation guarantee. Restart does not bypass that check.
This mode uses your user's permissions, not a restricted per-Connector token.
Least-privilege per-Connector credential issuance remains future platform work;
you do not need that feature to use host-session enrollment.

For unattended servers, use a service-account credential file:

```sh
datumctl connect up --project PROJECT --credentials-file /absolute/credentials.json
```

The daemon imports the file into private storage and refreshes these credentials
in-process, without invoking the host helper. Supported files are portal
`datum_service_account` JSON or the renewable OAuth credential format below.
Protect the source file with mode 600. Do not place a short-lived human access
token in this file. `daemon install --credentials-file FILE --system` supplies
credentials to a system service without depending on an interactive user login.

```json
{
  "type": "connector",
  "project_id": "PROJECT",
  "api_endpoint": "https://api.datum.net",
  "token_uri": "https://auth.datum.net/oauth/v2/token",
  "client_id": "CONNECTOR_CLIENT",
  "refresh_token": "RENEWABLE_CONNECTOR_CREDENTIAL"
}
```

```sh
datumctl connect serve localhost:8080 --project PROJECT
datumctl connect serve localhost:22 --project PROJECT --allow TEAMMATE_CONNECTOR_KEY
datumctl connect dial SERVER_CONNECTOR_KEY:22 --project PROJECT --bind 2222
datumctl connect hangup 2222 --project PROJECT
datumctl connect unserve localhost:22 --project PROJECT
datumctl connect down --project PROJECT
```

Without `--allow`, private access targets same-project MASQUE devices, excluding
gateway identities approved by your Connector's class and aliases of those
keys. Malformed or unresolved gateway approval fails closed. This exclusion
uses the current ConnectorClass contract; it does not certify policy across
multiple classes or platform-wide revocation behavior.
Use a destination such as `localhost:8080`, not the wildcard listen address
`0.0.0.0:8080` or `[::]:8080`.
An explicit allowlist selects the listed Connector identities. Explicitly
allowing a gateway can expose your service through that gateway's ingress.
Use `--protocol udp` on both `serve` and `dial` for UDP. Public HTTP ingress
requires TCP and an explicit `--public`; it cannot combine with `--allow`.
Each UDP dial supports up to 128 local client associations. Idle associations
expire after 60 seconds. This preview caps UDP payloads at 1,100 bytes and also
respects QUIC path limits. Oversized packets and packets that exceed bounded
receive queues are dropped without closing the association. Transport diagnostics
report these drops in `datagrams_dropped`.
Deleting a service removes only resources owned by its Connector. The daemon
refuses to adopt foreign resources or overwrite administrator-edited specs.

The daemon creates a unique key per local device/project enrollment. Restart
preserves that key. Peer addressing uses Connector public keys, not tickets.
The daemon periodically revalidates membership and fails closed when it cannot
confirm authorization. Deleting the Connector revokes the running enrollment;
normal reconciliation must not recreate it.

## Diagnose connectivity

Use `--verbose` to print CLI request timings and daemon request IDs. Use
`status` to distinguish desired state from running state and inspect the last
failure stage. The daemon emits structured JSON logs to stderr. Add
`--log-file /absolute/private/connect.log` for a file, and set `RUST_LOG` for
more detail:

```sh
RUST_LOG=info,datum_connect_daemon=debug,connect_transport=debug,connect_lib::successor=debug \
  datum-connect-daemon --repo /absolute/private/connect-state \
  --log-file /absolute/private/connect.log
```

Trace events cover API correlation, control-plane latency and status,
credential exchanges without token bodies, transport connections, and
authorization failures. Treat endpoint addresses, Connector IDs, and project
names as operational metadata. Restrict access to logs. Configure external log
rotation for long-running deployments. `/v1/audit?project=PROJECT` exposes
bounded local audit history; the store retains the most recent 500 events.
This history is not an immutable compliance audit trail.
Project-wide status includes transfer counters and the last observed direct or
relay path and RTT for public-key dials. These path observations are snapshots,
not a continuous path-quality monitor. Resource-scoped tokens cannot read
project-wide transport diagnostics.

## Platform contract and remaining work

| Area | Current behavior | Required follow-up |
| --- | --- | --- |
| Enrollment | Requires exactly one Ready Connect `ConnectorClass` whose `spec.transports` includes `masque-v1` | Deploy and validate the Connect class and controller |
| Public ingress | Requires approved gateway Connector identities in the class's `connect.datum.net/gateway-connectors` JSON-array annotation | Deploy the implemented edge in the production topology and certify HTTPProxy readiness |
| Credentials | Uses a pinned host login session through `datumctl auth get-token`, or imports renewable OAuth/service-account JSON with in-process refresh | Issue least-privilege, per-Connector credentials; host-session mode currently uses user permissions |
| Identity rotation | Restart and `up` refuse to recreate a revoked enrollment | Add an explicit administrator leave/rejoin workflow that rotates the key |
| VPC | Managed joins use `ConnectGateway` and `ConnectNetworkBinding`; the local adapter installs approved routes for the assigned address | Validate routing and packet forwarding on each supported host; the gateway and VPC firewall must allow the traffic |
| Desktop | Existing app remains unchanged | Convert it into a daemon client in `datum-cloud/app` |
| Packaging | Includes the daemon and architecture-matched pinned Wintun DLLs for Windows | Validate native services, Windows ACLs, signing, upgrades, and rollback on each OS |

This remains preview implementation, not a production-readiness claim. Windows
uses protected private ACLs for state, credentials, and daemon bearer files,
and a native SCM system service. Its interactive OIDC helper remains unsupported.
Native driver/service runtime verification still requires a Windows host. See the
[native adapter guide](../connect-lib/daemon/README.md#install-a-native-privileged-daemon).

Do not add capability annotations to an old gateway to bypass these gates.
They describe a deployment contract, not a substitute for a compatible gateway.
This branch makes a clean CLI break: the `tunnel` tree and its
supervisor are removed, and release archives no longer include the legacy
`datum-connect` executable. Migrate scripts to `serve --public` if they rely on
public URLs, or use private `serve` and `dial` together. Stop existing legacy
background processes with the previous CLI before upgrading. Local legacy
state is not silently imported or deleted. No release version changes to 1.0.0 until those dependencies
and cross-platform checks pass.

## Local verification caveat

Local workspace tests pass with the pinned Rust 1.98 toolchain and locked
dependencies. Go tests, race tests, and vet also pass on macOS. CI checks the
other supported platforms before a preview is published.
Native service verification covers macOS launchd. Linux systemd installation,
relay-only paths, and Windows native runtime behavior still need validation.
