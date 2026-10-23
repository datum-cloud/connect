# Project-less local tunnels (`datumctl connect local`)

Status: proposal. Base: `v1.0.0-preview.28`.

## Goal

Anyone with `datumctl` and the Connect plugin can share a local service with
their own devices without a Datum account, organization, or project:

```sh
datumctl connect local --port 9999
```

The command prints a ticket and a QR code. A phone running the Datum Connect
Android app scans it and opens `http://localhost:8888` in its browser. Another
computer runs `datumctl connect dial TICKET --bind 8888`. Traffic goes peer to
peer over iroh with the same MASQUE CONNECT-TCP transport as project-scoped
Connect. It falls back to a relay only when a direct path fails.

In scope:

- `datumctl connect local` (sharer) and project-less `datumctl connect dial
  TICKET` (peer).
- A new Android app that pairs by QR code and serves the shared service on a
  phone-local port. No login.
- The `connect-share` Rust crate that both use.

Later, not in this proposal's first phase:

- iOS. It needs a Network Extension; see [iOS](#ios).
- Public URLs for browsers without an iroh client. See
  [Public URLs](#later-public-urls).

Non-goals:

- Hostnames, or identities beyond one share's key, without an account.
  Signed-in users keep `serve`, `dial`, and `serve --public`. A share may keep
  its own key so its ticket survives restarts; see [Lifetime](#lifetime).
- Raw UDP and VPC (`join`) without an account.

## What exists today

Connect has no project-less mode. Every cloud-facing path needs a project:

| Layer | Where the project is required |
|---|---|
| Plugin | `project()` errors if neither `--project` nor the datumctl context names one (`connect-plugin/commands/root.go:80`). `serve`, `up`, `dial`, `join`, and `ping` also run the service-catalog gate (`connect-plugin/commands/activation.go:20`). |
| Daemon credentials | Every credential kind carries `project_id`. `CloudConnector::new` rejects a mismatch (`connect-lib/lib/src/successor/mod.rs:156`). |
| API paths | Every call goes to `/apis/resourcemanager.miloapis.com/v1alpha1/projects/{p}/control-plane` (`successor/mod.rs:168`). |
| Peer allowlists | The daemon resolves allowed peers from Connector objects in the project (`successor/mod.rs:1017`). |

datumctl itself does not block anonymous use. Plugin dispatch exports empty
`DATUM_SESSION` and `DATUM_PROJECT` values and leaves it to the plugin to decide
(`datumctl/internal/plugindispatch/dispatch.go:149`). No datumctl change is
required.

The project gives Connect two things: a place to publish a Connector's address,
and an authority for which peers may connect. Without a project, the ticket
carries the address and the pairing secret replaces the authority.

## Design

```
  laptop                                                     phone or second computer
┌──────────────────────────────┐                           ┌──────────────────────────────┐
│ datumctl connect local       │   1. ticket (QR / text)   │ Android app or               │
│   └ datum-connectd local     │ ────────────────────────▶ │ datumctl connect dial TICKET │
│       in-memory iroh key     │                           │   iroh key                   │
│       pairing ALPN           │ ◀── 2. pair: secret ───── │                              │
│       MASQUE listener        │     (peer ID from TLS)    │                              │
│         allow: paired IDs    │                           │                              │
│                              │ ◀── 3. CONNECT-TCP ────── │ localhost:8888 ◀── browser   │
│   └ localhost:9999           │     direct or via relay   │                              │
└──────────────────────────────┘                           └──────────────────────────────┘
```

No Datum service is in the path except iroh relays, and only when hole punching
fails.

### Ticket

`connect-lib/share/src/ticket.rs`. Text form: `DATUMTUN1` followed by
unpadded RFC 4648 base32 of a compact binary encoding. Parsing ignores case
and also accepts `DCSHARE2`, the prefix before the rename. The prefix ends in
`1`, which base32 never uses, so a search for the prefix in pasted text can't
match a word such as `datumctl`.

| Field | Encoding |
|---|---|
| version | 1 byte (`1`) |
| endpoint id | Sharer's iroh EndpointId, 32 bytes |
| secret | 32 random bytes |
| port | Shared port, 2 bytes; the MASQUE destination is `tcp-<port>` |
| relays | Count, then length-prefixed URLs (at most 4) |
| addresses | Count, then IPv4 or IPv6 address and port (at most 6), including LAN addresses |

A typical ticket is about 230 characters, all uppercase letters and digits.
That is the QR alphanumeric set, so the QR code uses alphanumeric mode and fits
in about version 9 (53 modules) instead of version 13 (69 modules) for the
earlier JSON-and-base64url form. The first device test showed the larger code
did not scan from a terminal.

The ticket is a bearer secret for as long as the sharer runs. Anyone who has
it can pair, up to the peer limit. It also reveals the sharer's IP addresses.
The CLI and the app say so when they display it.

### Pairing

`connect-lib/share/src/pair.rs`, ALPN `datum-connect/share-pair/1`.

1. The peer connects to the sharer on the pairing ALPN from the same iroh key
   it will use for traffic.
2. It sends `{"secret": "...", "name": "Pixel 8"}` on one stream.
3. The sharer compares the secret in constant time. It takes the peer's
   EndpointId from the authenticated QUIC connection, never from the request.
4. On success, the sharer adds that EndpointId to the destination's
   `Access::Peers` and replies `{"ok": true, "name": "laptop:9999"}`. It
   reports the pairing on stdout so the user sees which device joined.

The `name` in the reply is the share's display name, set with
`datumctl connect local --name` and defaulting to `HOSTNAME:PORT`. It travels
in the pairing reply rather than the ticket, so tickets and QR codes stay the
same size and older apps keep working. Both sides drop control characters and
cap names at 64 characters.

Until a peer pairs, the destination's allowlist is empty and every MASQUE
request is refused. Pairing closes after `--max-peers` distinct devices
(default 4). A device that pairs again is accepted and does not count twice.

Why pair instead of putting the secret in each CONNECT request: the transport
already authorizes by peer EndpointId (`Access::Peers`). Pairing keeps that
model unchanged, needs no new header, and means a ticket leaked after the
limit is reached grants nothing.

The pairing handler shares the transport's endpoint and identity. To allow
this, `connect-transport` gained `TransportConfig::protocol(alpn, handler)`,
which registers an extra ALPN on the transport's own accept loop. The MASQUE
and CONNECT-IP ALPNs cannot be replaced.

### Lifetime

By default everything lives in memory. The sharer generates a new key on each
run, so every run prints a new ticket, and stopping the command revokes all
pairings. Nothing is written to disk on the sharer.

A share can instead keep a `ShareKey`: its iroh secret key, pairing secret, and
destination port, in a file such as `--key-file`, written with mode 0600 and
refused when other users can read it. A run with the same key prints a ticket
with the same identity and secret, so tickets from earlier runs still pair, and
devices with a saved ticket reconnect without scanning again. The direct
addresses in an old ticket may be stale. Peers still find the sharer by its
EndpointId through the transport preset's address lookup, which publishes the
sharer's current addresses to n0's DNS.

The key's port names the destination, so the service may move to another local
port without breaking old tickets. Paired peers are still kept only in memory;
returning devices pair again with the secret, and `--max-peers` counts per run.
To revoke a kept ticket, delete the key file, or in the apps choose New ticket.

### Relays

Decision (2026-10-16): use n0's public relays for now. Without
`--relay-urls`, the transport uses them already
(`connect-lib/transport/src/lib.rs:246`), as `serve` does outside staging, so
anonymous clients add no load to Datum relays. Revisit if n0's relays become a
reliability or policy concern. Moving to Datum relays would then need relay
access controls and rate limits for anonymous clients.

An empty relay list disables relays.

### Direct paths behind a load balancer

A share on Datum Compute is reached through a relay today. The instance sends
from a translated public IPv6 address, and unsolicited inbound UDP does not
reach it, so iroh cannot set up a direct path. A tested share on a unikernel
instance stayed relayed at about 70 ms.

Two share options prepare for a regional Layer 4 load balancer
(datum-cloud/galactic#698), which forwards TCP and UDP to a backend without a
proxy and answers from its public address:

- `--udp-port PORT` binds iroh's UDP socket to a fixed port, for IPv4 and
  IPv6, instead of a random one, so a load balancer rule can forward to it.
- `--public-addr IP:PORT` (repeatable) adds the load balancer's address to the
  ticket. iroh only discovers the address it sends from, so it cannot find
  this one itself. Public addresses always fit in the ticket's six-address
  limit; discovered addresses fill the remaining slots.

The diagnostics program reads the same settings from `UDP_PORT` and
`PUBLIC_ADDRS`. Then only direct addresses are used,
which suits a phone on the same Wi-Fi and offline tests.

## Components

### `connect-share` crate (new, implemented)

`connect-lib/share`. No cloud, auth, or storage dependencies. Depends only on
`connect-transport`, `iroh`, `tokio`, and serde.

| API | Purpose |
|---|---|
| `share(ShareOptions, cancel, on_event)` | Sharer. Emits `Ready { ticket }` and `Paired { peer, name }`. |
| `dial(DialOptions, cancel, on_ready)` | Peer. Pairs, binds a local TCP listener, forwards each connection. Accepts a caller-supplied key so a device can keep one identity. |
| `ShareTicket` | `Display` and `FromStr` for the text form. |
| `ShareKey` | A share's identity, secret, and port, kept so its ticket survives restarts. Text form `DATUMKEY1…` (earlier `DCKEY1…` still parses); `load_or_create` keeps it in a 0600 file. |

### `datum-connectd` foreground modes (implemented)

```text
datum-connectd local HOST:PORT [--max-peers N] [--relay-urls URLS] [--key-file PATH]
datum-connectd local-dial TICKET [--bind ADDR] [--name NAME] [--relay-urls URLS]
```

Both write one JSON event per line on stdout (`share_ready` with the ticket,
`share_paired`, `dial_ready`) and JSON logs on stderr. Neither opens the
daemon repository, credentials, or the loopback API.

### Plugin commands (implemented)

```text
datumctl connect local --port PORT [--host HOST] [--name NAME] [--key-file PATH]
datumctl connect local HOST:PORT [--name NAME]
datumctl connect dial TICKET [--bind PORT]
```

- `local` skips `project()` and the service-catalog gate. Add it to the
  ungated list in `activation.go`.
- `dial` keeps its project behavior when the argument is `CONNECTOR:PORT`. When
  the argument starts with `DATUMTUN1` (or `DCSHARE2`), it skips the project and runs
  `local-dial`.
- Both run in the foreground and exec `datum-connectd`, which the plugin
  already downloads and verifies. They do not install the background daemon.
- `local` prints the ticket, a terminal QR code, and each device that pairs.
- Both ignore any datumctl session. The output is the same whether or not the
  user is signed in.

### Android app (new)

A new, standalone app. It has no login and no Datum Cloud dependency, so it
does not build on the existing desktop-app port
(`datum-cloud/app`, branch `feat/android-build`), which requires an account.

**Architecture**

| Layer | Choice | Why |
|---|---|---|
| Core | `connect-share` through a thin `connect-share-ffi` crate with UniFFI bindings | One implementation of the ticket, pairing, and wire protocol for CLI and phone. |
| UI | Kotlin, Jetpack Compose | Foreground services, camera, and notifications are native Android APIs. |
| QR scanning | ZXing (`zxing-android-embedded`) | Works offline and without Google Play services. ML Kit is an option for a Play-only build. |
| Native build | `cargo-ndk` for `arm64-v8a`, `armeabi-v7a`, `x86_64` | `x86_64` for the emulator. |

The FFI surface is small: parse a ticket, start a dial with a key and a bind
port, stop it, and a callback for state changes.

**Behavior**

- Scan a QR code or paste a ticket. Show the sharer's port and EndpointId
  prefix before connecting.
- Hold any number of connections at once, each on its own local port. Adding
  one never stops another. Each card offers Open, Stop, Rename, and, once
  stopped or failed, Reconnect and Remove.
- Name each connection. A new connection takes the name the sharer sends,
  made unique with a " (2)" suffix if needed, unless the user typed one when
  adding it. Names can be changed later and must be unique, ignoring case.
- Bind `127.0.0.1` on the shared port when it is 1024 or higher and no other
  connection uses it, otherwise on a port the user picks or the system
  assigns. Android shares loopback between apps, so Chrome can reach it.
- Run every dial in one foreground service with a persistent notification that
  lists the open connections and has a Stop all action. Android 14 requires a
  foreground service type; use `specialUse` with a description of the local
  proxy. The service stops when no connection is active.
- Keep one device key in app-private, no-backup storage (`noBackupFilesDir`),
  so a dropped connection can resume against the same sharer run without
  pairing again. The key never leaves the phone and is excluded from backups.
- Save every connection's name, ticket, and port to app-private storage after
  each change, so the list survives restarts and updates. Saved connections
  come back stopped. Backups stay off, as in the WireGuard app, so tickets
  never leave the phone; uninstalling deletes them.
- Export and import the list as a JSON file. Export requires a fingerprint or
  the screen lock and refuses on a phone without one. The device key is never
  exported.
- Build debug versions as a separate app (`net.datum.connect.share.debug`) so
  a debug build signed with a developer's key can never block a release
  update and force an uninstall.
- Stop the service when the user taps Stop, or when the sharer has been
  unreachable for a set time.

**Distribution**

During development, `connect-mobile/android/scripts/share-apk.sh` serves a
new build to a phone that already has the app, over a project-less share. No
public URL is needed after the first install.

For users without the app: a release-signed APK in the public `datum-download`
S3 bucket (account 007091975061, us-east-2), published with
`scripts/publish-apk.sh` as `datum-connect-YYYYMMDD-<sha256[:12]>.apk` with a
download page at
<https://datum-download.s3.us-east-2.amazonaws.com/connect/index.html>.
GitHub releases and the Play Store can follow.

The same page, <https://datum-download.s3.us-east-2.amazonaws.com/connect/index.html>,
offers Linux and macOS archives of `datumctl-connect` and `datum-connectd`
for people without `datumctl`, with instructions for pairing two devices.
`scripts/build-linux-share.sh` builds the Linux x86_64 and arm64 archives in an
Ubuntu 22.04 container (glibc 2.34+, OpenSSL 3).
`scripts/build-macos-share.sh` builds the arm64 and x86_64 macOS archives and
must run on a Mac; the binaries are not notarized, so the page installs them
with `curl`. `scripts/downloads/publish-cli.sh linux|macos` publishes either
set.

Keep signing keys in CI secrets. The existing app branch commits keystore passwords in
`ui/Dioxus.toml`; do not repeat that.

**Where it lives**

Decision (2026-10-16): in this repository, at `connect-mobile/android/`
beside `connect-lib`, so the wire protocol and the app change in the same pull
request. The FFI crate goes
in the Rust workspace as `connect-lib/share-ffi`.

### iOS

iOS suspends an app's sockets soon after it leaves the foreground. A local
port served by the app stops working when the user switches to Safari. The
working option is a `NEPacketTunnelProvider` Network Extension, which makes the
phone a CONNECT-IP client like `join`. That is a larger, separate design.

## Later: public URLs

For viewers without an iroh client, a shared Quick Tunnel Gateway on Datum
Compute can bridge HTTPS to the same transport. An earlier revision of this
document proposed it in detail. In summary:

- A Compute Workload runs a front that terminates HTTPS for
  `*.<quick-domain>` and serves a broker API. Behind it runs an `iroh-gateway`
  sidecar from branch `feat/masque-connect`, which already forwards HTTP
  origin requests over MASQUE CONNECT-TCP when given `x-iroh-endpoint-id` and
  target headers. A laptop test on 2026-10-16 confirmed that path.
- It depends on Compute Workloads receiving traffic directly from the
  internet, which is planned.
- It needs a separate registrable domain, abuse controls, and a gateway
  address-hint header in `iroh-gateway`.

`datumctl connect local --public` would register with that gateway and add its
identities to the allowlist, alongside paired peers.

## Security summary

| Risk | Control |
|---|---|
| Ticket leaks | Pairing limit; ticket dies when the sharer stops, or with a kept key when the key is deleted or rotated; the UI warns that the ticket is a secret |
| Kept key file leaks | Written 0600 and refused if others can read it; the key alone lets anyone impersonate the share |
| Peer impersonation | Peer identity comes from the iroh TLS handshake, not from the request |
| Secret guessing | 256-bit secret, constant-time comparison |
| Exposure of the sharer's other ports | Only `tcp-<port>` is advertised; the transport refuses other destinations |
| IP address disclosure | Ticket includes direct addresses; documented in the UI |
| Anonymous relay use | n0's public relays carry it for now (see [Relays](#relays)) |

## Implementation status

On branch `feat/projectless-local-tunnel`:

| Piece | Status |
|---|---|
| `connect-transport` extra ALPN handlers | Done |
| `connect-share`: ticket, pairing, share, dial | Done; 5 unit and 3 loopback end-to-end tests |
| `datum-connectd local` and `local-dial` | Done; tested across two processes over n0 relays, including a tampered-secret refusal |
| Plugin `local` and ticket `dial`, terminal QR code | Done; e2e test against a real `datum-connectd` with relays disabled (`task test:e2e:local`) |
| `connect-share-ffi` (UniFFI) | Done; Kotlin bindings tested on the host JVM, including a dial through a real `datum-connectd local` |
| Android app (`connect-mobile/android`) | First version builds for arm64-v8a, armeabi-v7a, and x86_64. On 2026-10-16 a Pixel 9a pasted a ticket, paired with `datum-connectd local` over n0 relays, and loaded the shared page in Chrome. On 2026-10-17 it scanned a `DCSHARE2` QR code from a terminal and connected. Network changes not yet tested |
| `nix develop .#android` shell | Done |
| Relay policy | Decided: n0 public relays for now |

## Work breakdown

1. Finish device testing: behavior across network changes and long app
   switches.
2. Move the release keystore into a secrets store and publish from CI;
   remembered tickets.
3. Later: public URLs through the Quick Tunnel Gateway; iOS Network Extension.
