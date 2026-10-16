# Project-less local tunnels (`datumctl connect local`)

Status: proposal. Base: `v1.0.0-preview.28`.

## Goal

Anyone with `datumctl` and the Connect plugin installed can run:

```sh
datumctl connect local --port 9999
```

and receive a public HTTPS URL that forwards to `localhost:9999` for as long as
the command runs. It needs no `datumctl login`, no organization, and no project.
This is the same experience as `cloudflared tunnel --url` or anonymous ngrok.

Non-goals:

- Persistent or custom hostnames. Those stay with `serve --public`.
- Raw TCP, UDP, or VPC (`join`) access without an account.
- Private or peer-to-peer sharing (`dial`) without an account.

## What exists today

Connect has no project-less mode. Every cloud-facing path needs a project:

| Layer | Where the project is required |
|---|---|
| Plugin | `project()` errors if neither `--project` nor the datumctl context names one (`connect-plugin/commands/root.go:80`). `serve`, `up`, `dial`, `join`, and `ping` also run the service-catalog gate (`connect-plugin/commands/activation.go:20`). |
| Daemon credentials | Every credential kind carries `project_id`. `CloudConnector::new` rejects a mismatch (`connect-lib/lib/src/successor/mod.rs:156`). |
| API paths | Every call goes to `/apis/resourcemanager.miloapis.com/v1alpha1/projects/{p}/control-plane` (`successor/mod.rs:168`). |
| Edge allowlist | The serving daemon looks up approved edge Connectors by name inside the user's project (`successor/mod.rs:1125`). |
| Architecture | `docs/architecture/multi-tenancy.md` says there is "no host-global service publication". |

datumctl itself does not block anonymous use. Plugin dispatch exports empty
`DATUM_SESSION` and `DATUM_PROJECT` values and leaves it to the plugin to decide
(`datumctl/internal/plugindispatch/dispatch.go:149`). No datumctl change is
required.

The closest prior work is the removed legacy `datum-connect tunnel` path. It
used codename hostnames under `iroh.datum.net` (`connect-lib/lib/src/lib.rs:35`),
but it also required a project.

## Design summary

The platform runs one shared **Quick Tunnel Gateway** as a Datum Compute
Workload that receives traffic directly from the internet. It serves every
anonymous tunnel. Each instance runs two containers:

1. **`quick-tunnel-front`** (new). Serves the broker API, which registers a
   tunnel for an anonymous client, assigns a hostname, and tracks a short
   lease. It also terminates HTTPS for `*.<quick-domain>`, maps the `Host`
   header to the client's iroh EndpointId, and applies abuse controls.
2. **`iroh-gateway`** (existing, branch `feat/masque-connect`). Receives the
   rewritten request on loopback and opens a MASQUE CONNECT-TCP stream to the
   client over iroh.

This is the same split the edge already uses: Envoy picks the target and sets
headers, and an `iroh-gateway` sidecar carries the bytes
(`infra/apps/network-services-operator/downstream/base/downstream-gateway.yaml`).

```
                               Quick Tunnel Gateway (Compute Workload, N instances)
                              ┌───────────────────────────────────────────────────────────┐
browser ──HTTPS──────────────▶│ quick-tunnel-front                                        │
  *.<quick-domain>            │   TLS, Host → tunnel, limits, interstitial                │
                              │   sets x-iroh-endpoint-id, x-datum-target-{host,port}     │
datumctl connect local ─HTTPS▶│   broker API: register / renew / delete                  │
  (register, renew)           │        │ loopback HTTP                                    │
                              │        ▼                                                  │
                              │ iroh-gateway --transport masque                           │──iroh/QUIC──▶ datumctl connect local ──TCP──▶ localhost:9999
                              │   connect-transport connect_tcp                           │  CONNECT-TCP   (Access::Peers = gateway IDs)
                              └───────────────────────────────────────────────────────────┘
                                       │ QuickTunnel objects (shared state)
                                       ▼
                              platform project control plane
```

The client holds no control-plane credential. It holds:

1. an ephemeral iroh keypair, generated in memory and discarded on exit, and
2. an opaque lease token that can renew or delete exactly one tunnel.

### Why one shared gateway

This creates no per-tunnel Connector, ConnectorAdvertisement, or HTTPProxy.
That removes three problems the earlier draft had:

- HTTPProxy does not support wildcard hostnames
  (`network-services-operator/api/v1alpha/httpproxy_types.go:47`), and NSO
  assigns default hostnames from one global target domain. A per-tunnel
  HTTPProxy would need NSO changes to use a separate domain.
- Project quota on Connectors and HTTPProxies would have to scale with
  anonymous traffic.
- Each tunnel would wait for NSO to program Envoy and report
  CertificatesReady. The gateway can route a new hostname as soon as it is
  registered.

The cost is that this ingress does not sit behind the edge Envoy fleet, so the
gateway must do its own rate limiting and abuse controls.

## Components

### 1. CLI: `datumctl connect local`

```text
datumctl connect local --port PORT [--host HOST]
datumctl connect local HOST:PORT
```

Behavior:

- Runs in the foreground. Ctrl+C deletes the tunnel. It does not install or
  require the background daemon, and it writes no files under the repo dir.
- Skips `project()` and the service-catalog gate. Add `local` to the
  "no gate" list in `activation.go`.
- Ignores any datumctl session, even if one exists. The output is the same
  whether or not the user is logged in.
- Prints the URL, the expiry, and a hint:
  `For a stable hostname, sign in and run: datumctl connect serve localhost:9999 --public`.
- HTTP only, including WebSocket upgrades.

Where the code runs: the Go plugin cannot speak iroh. Add a foreground
subcommand to the Rust daemon binary, `datum-connectd local`, and have the
plugin exec it. The plugin already downloads and verifies `datum-connectd`.
The subcommand:

1. creates an iroh endpoint with the gateway's relay URLs,
2. registers with the gateway's broker API,
3. starts a `connect-transport` server with one destination,
   `DestinationId::tcp(port)` → `localhost:PORT`, and
   `Access::Peers(gatewayPeers)`,
4. renews every 15 s and updates `gatewayPeers` from each renewal response,
5. deletes the tunnel on exit.

It does not open the store, the loopback API, or the control-plane client.
`Access::Peers` keeps the existing rule from
`connect-lib/daemon/src/runtime.rs:209`: public means approved gateway
identities, never arbitrary peers.

### 2. Quick Tunnel Gateway

#### `iroh-gateway` sidecar (existing)

The `ConnectGateway` image `ghcr.io/datum-cloud/iroh-gateway:v0.0.0-357f82b`
is built from `iroh-gateway` branch `feat/masque-connect`. That branch:

- depends on `connect-transport` from this repository;
- accepts an HTTP origin request with `x-iroh-endpoint-id`,
  `x-datum-target-host`, and `x-datum-target-port`, strips those headers, and
  forwards the request with `connect_tcp` to `DestinationId::tcp(port)` on
  that endpoint (`src/gateway.rs:304`, `src/gateway/masque.rs:358`);
- binds to `127.0.0.1` by default in MASQUE mode, and can also serve a Unix
  socket (`masque::serve_uds`);
- has no authorization of its own, so it must stay on loopback behind the
  front.

Run it with `--transport masque` and the instance's key from a Secret.

Two gaps to close in `iroh-gateway`:

1. **Merge `feat/masque-connect` to `main`.** The production `ConnectGateway`
   image is already built from it.
2. **Address hints.** The gateway finds a peer's address through iroh
   discovery (`default`, `dns`, or `hybrid`). Quick-tunnel clients have no
   Connector, so NSO publishes no `_iroh` DNS record for them, and we do not
   want to depend on n0's discovery. Add a trusted request header, for example
   `x-iroh-endpoint-addr`, that carries the client's relay URL and direct
   addresses. The gateway strips it like the other Datum headers. The front
   sets it from the address the client registered.

#### `quick-tunnel-front` (new)

A new binary, built in this repository. It has no iroh code of its own; all
iroh traffic goes through the sidecar.

#### Broker API

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/challenges` | none | Returns `{nonce, difficulty, expiresAt}`. |
| `POST /v1/tunnels` | signed nonce plus proof of work | Creates a tunnel. |
| `PUT /v1/tunnels/{id}/lease` | lease token | Renews. Returns current `gatewayPeers`. |
| `DELETE /v1/tunnels/{id}` | lease token | Deletes immediately. |
| `POST /v1/abuse` | none | Reports a hostname. |

Served at a fixed name, for example `https://quick.connect.datum.net`.

Create request:

```json
{
  "publicKey": "<64 hex iroh EndpointId>",
  "endpoint": "<serialized EndpointAddr: relay URL plus direct addrs>",
  "port": 9999,
  "nonce": "...",
  "signature": "<ed25519 signature of nonce || publicKey by the iroh key>",
  "work": "<proof-of-work solution>",
  "client": {"version": "1.0.0-preview.29", "os": "linux", "arch": "amd64"}
}
```

The signature proves the caller owns the key. Without it, a caller could
register someone else's EndpointId and send them unwanted traffic.

Create response:

```json
{
  "id": "qt-7f3c...",
  "url": "https://amber-otter-k2x9.<quick-domain>",
  "leaseToken": "<opaque, 256-bit>",
  "leaseSeconds": 30,
  "expiresAt": "2026-10-16T23:00:00Z",
  "gatewayPeers": ["<replica EndpointId>", "..."]
}
```

#### Ingress

- Listens on TCP 443 with a wildcard certificate for `*.<quick-domain>`.
- Looks up `Host` in the tunnel table. An unknown host gets 404. An expired
  lease gets 502 with a short "tunnel offline" page.
- Strips any client-supplied `x-iroh-*` and `x-datum-*` headers, then sets
  `x-iroh-endpoint-id`, `x-iroh-endpoint-addr`, `x-datum-target-host:
  localhost`, and `x-datum-target-port` from the tunnel record, and forwards
  to the sidecar on loopback. HTTP/1.1, HTTP/2, and upgrades pass through.
- Adds `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host`.
- Shows an interstitial page on the first browser visit to each hostname. It
  says the site is an anonymous tunnel and sets a cookie. API clients skip it
  by sending a documented header. This is the main phishing deterrent that
  ngrok and others use.
- Applies per-hostname request-rate, concurrent-stream, bandwidth, and body
  size limits.

#### State

Store each tunnel as a `QuickTunnel` object in the platform project:
`{hostname, publicKey, endpoint, port, sha256(leaseToken), sourceIP, created,
expires, renewedAt}`. Every replica watches the objects and keeps an in-memory
Host → tunnel map. Any replica can then serve any tunnel, because the gateway
dials the client through iroh. Operators can inspect and delete tunnels with
`datumctl get` and `datumctl delete`.

A sweeper deletes objects whose lease is more than 30 s old (two missed
renewals) or that are past the hard TTL.

#### Identity

Each instance's `iroh-gateway` has its own iroh key, mounted from a Secret,
the way connect-controller provisions `ConnectGateway` keys
(`connect-controller/internal/controller/connectors.go:565`). Do not share one
key across instances, because two live endpoints with the same EndpointId
conflict at the relay. The front reads the sidecar's EndpointId at startup and
records it, so the broker can return every instance's EndpointId in
`gatewayPeers`. Because clients re-read it on each renewal, instances can be
added or replaced without dropping tunnels.

### 3. Deployment on Datum Compute

- A platform project, for example `datum-quick-tunnels`, under a platform org.
  Do not reuse `datum-cloud`; it already holds shared infrastructure
  credentials (`infra/apps/external-dns-webhook/production/webhook-kubeconfig.yaml`).
- A Compute Workload with the two containers above, in several locations,
  managed from `infra`. This assumes Compute Workloads can receive traffic
  directly from the internet, which is planned. Each instance needs inbound
  TCP 443 and UDP for iroh.
- A service account for the workload, with a role that can only manage
  `QuickTunnel` objects in that project.
- Datum relays only (`iroh-relay.*`). The gateway passes its relay URLs to
  clients so tunnels do not fall back to n0's public relays
  (`connect-lib/transport/src/lib.rs:246`).
- DNS: `*.<quick-domain>` resolves to the gateway instances, for example by
  GeoDNS to the nearest location.

### 4. Domain

Use a separate registrable domain for quick tunnels, not `datumproxy.net`.
Anonymous tunnels attract phishing. Blocklists act on whole registrable
domains, so a shared domain would put paying customers' hostnames at risk.
Submit the domain to the Public Suffix List so browsers isolate cookies between
tunnels. Staging can use a subdomain of a staging domain.

### 5. Abuse handling

| Control | Default |
|---|---|
| Hard TTL per tunnel | 8 hours |
| Lease timeout | 30 s without renewal |
| Concurrent tunnels per client IP (/64 for IPv6) | 2 |
| Creates per client IP per hour | 10 |
| Proof-of-work difficulty | Raised automatically when the create rate spikes |
| Global kill switch | Config flag that rejects all creates |
| Takedown | `POST /v1/abuse` plus an operator command that deletes the tunnel and blocks its key and source IP |
| Record retention | Hostname, public key, source IP, and timestamps, kept 30 days for abuse response |

The FraudProvider proposal
(`enhancements/enhancements/platform/fraud-and-abuse/README.md`) scores users at
signup and does not cover unauthenticated traffic. The gateway can call it with
the source IP later, if it gains an IP-scoring API.

## Open questions

1. **Direct internet ingress on Compute.** This design assumes it, and it is
   planned. Until it ships, staging can front the workload with a single
   HTTPProxy per test hostname, because HTTPProxy has no wildcard hostnames.
2. **Proof of work vs. a challenge page.** A CLI cannot show a CAPTCHA. Proof
   of work raises the cost of mass creation but does not stop a determined
   abuser. Per-IP limits and takedown do the rest.
3. **Should a logged-in user get more?** This proposal says no. Logged-in users
   should use `serve --public`, which already gives a stable hostname under
   their own project and quota.

## Work breakdown

| Repo | Change | New? |
|---|---|---|
| `connect` | `datumctl connect local` in the plugin; skip project and catalog gate | Change |
| `connect` | `datum-connectd local` foreground mode with broker client | New code |
| `connect` | `quick-tunnel-front` binary: broker API, HTTPS ingress, header rewrite, limits, sweeper | New service |
| `connect` | `QuickTunnel` CRD | New API |
| `iroh-gateway` | Merge `feat/masque-connect`; add the `x-iroh-endpoint-addr` address-hint header | Change |
| `infra` | Platform project, service account, role, Compute Workload, Secrets, domain, DNS, wildcard certificate | New config |
| `enhancements` | Enhancement proposal, abuse policy, and terms of use for anonymous tunnels | New doc |

Suggested order:

1. On a laptop: run `iroh-gateway --transport masque` from
   `feat/masque-connect` and send it hand-written headers to reach
   `datum-connectd local` with a hard-coded gateway peer. This proves the data
   path before any new service exists.
2. Address-hint header in `iroh-gateway`.
3. `quick-tunnel-front` with a static tunnel table, then the broker API and
   `QuickTunnel` state.
4. Staging deployment on Compute with a staging domain.
5. Plugin `local` command.
6. Abuse controls, production domain, and launch.
