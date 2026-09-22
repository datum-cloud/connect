# VPC Attachment (`connect vpc`)

Status: **Scaffolding — data plane implemented, control plane imagined**
Owner: connect team
Related: `datum-cloud/enhancements#894`, branch `vpc-894`

## 1. Problem statement

From the originating issue: a user wants `datumctl connect vpc` to produce a
local interface analogous to what a desktop WireGuard client gives them —
join a Datum Cloud galactic VPC (gVPC, IPv6-only) remotely, with the choice
of routing only VPC-bound traffic through it, or making it the default
route.

## 2. Architecture summary

`tunnel` and `vpc` are mirror images, both built on the same iroh
`Connector` primitive:

| | `tunnel` (existing) | `vpc` (this feature) |
|---|---|---|
| Client exposes vs. joins | exposes a local **service** | joins a **network** |
| Payload over the iroh/QUIC stream | HTTP requests (L7, `IROH_HTTP_CONNECT_ALPN`) | length-prefixed IP packets (L3, `IROH_VPC_ALPN`) |
| Who dials whom | Envoy dials the client | galactic-side router dials the client, once it claims the attachment |
| Datum Cloud-side terminator | Envoy + extension server | a galactic-side router component (**imagined** — see §5) |
| Client-side kernel object | none | a local TUN interface |

The client is the **accept side** in both cases — `vpc join` builds its own
iroh `Endpoint`/`Router` (`VpcListener`, `lib/src/vpc/mod.rs`), structurally
parallel to `tunnel`'s `ListenNode` but deliberately independent of it (own
iroh identity, own ALPN, own — future — CRD), so this feature cannot regress
`tunnel`'s accept path.

## 3. Data-plane protocol (`lib/src/vpc/transport.rs`)

- **ALPN**: `datum-connect/vpc/0`, distinct from `iroh_proxy_utils`'s HTTP
  CONNECT ALPN — there is no HTTP request/target here, just raw packets, so
  reusing `tunnel`'s proxy protocol doesn't apply.
- **Framing**: a 2-byte big-endian length prefix per packet over a single
  bidirectional QUIC stream. A QUIC stream is an ordered reliable byte
  stream, not message-preserving, so packet boundaries from the TUN
  device's discrete reads must be reconstructed explicitly. A future
  iteration may move this onto QUIC datagrams instead (message-preserving,
  and a closer match to IP's own best-effort delivery model), once the
  stream-based version is proven.
- **Peer identity check**: the accept handler is constructed with an
  optional single allowed remote `EndpointId` (the claimed router) and
  rejects any other dial-in. This is WireGuard's AllowedIPs *source filter*
  collapsed to a single peer — see §4. When no router has claimed the
  attachment yet (or, in this scaffold, when the caller omits
  `--router-id`), the handler accepts any dialer — a real,
  trust-on-first-connect window that exists in the CRD-backed flow too
  (a client necessarily starts before any router has claimed it), but which
  must never become the production default once a real control plane can
  populate `routerEndpointId` — see §6.

### Why WireGuard-linux's design was the reference, and what didn't carry over

iroh already provides the encrypted, authenticated, NAT-traversing
transport a WireGuard-style tunnel would otherwise need its own Noise
handshake, cookie mechanism, and endpoint-roaming logic for. What
WireGuard-linux's design *did* resolve:

- **Device model**: WireGuard is a real kernel `net_device`, not a
  userspace-wrapped TUN — but that's purely a performance choice (avoiding a
  userspace round-trip) that doesn't matter next to iroh's own QUIC/crypto
  overhead. A standard userspace TUN device (the `tun` crate,
  `create_tun_device`) is the right call here: no kernel module, works
  unprivileged-adjacent (`CAP_NET_ADMIN` only), and the OS still treats it
  as a normal interface for `ip addr`/routing/up-down.
- **AllowedIPs**: `allowedips.c` is a per-peer longest-prefix-match trie used
  both to route outbound packets to the right peer *and* to reject inbound
  packets whose source doesn't match that peer's allowed set. With exactly
  one peer (the router), the routing half collapses to a boolean —
  `Mode::VpcOnly` vs `Mode::DefaultRoute` (`lib/src/vpc/mod.rs`) — and the
  anti-spoof half becomes the single-`EndpointId` check above, enforced by
  the transport layer instead of a trie.
- **Keepalive & endpoint roaming**: both exist in WireGuard purely because
  raw UDP has no connection state or NAT-rebinding awareness. iroh (QUIC)
  already owns liveness, idle-timeout, NAT traversal, and connection
  migration — reimplementing either would be redundant.
- **MTU**: WireGuard computes its interface MTU as the path MTU minus its
  own header/crypto overhead, never guessing a flat 1500. The default MTU
  here (1280, the IPv6 minimum) follows the same discipline conservatively;
  deriving it precisely from iroh's own per-path overhead is a documented
  follow-up (see §6).
- **The routing-mode installation itself borrows from `wg-quick`, not the
  kernel module**: the kernel driver only *enforces* AllowedIPs, it's
  `wg-quick`'s shell script that translates AllowedIPs into `ip route`
  calls — which is exactly the shape `lib/src/vpc/routing.rs` takes,
  including `wg-quick`'s `::/1` + `8000::/1` split-default trick for
  `DefaultRoute` mode (so a real `::/0` is never displaced) and its
  anti-loop gotcha: pinning an explicit host route for the router's own
  transport address via the pre-existing default gateway *before* installing
  the split-default routes, so the tunnel's own iroh traffic doesn't get
  routed back into the interface it just created.

## 4. The CRD contract (`lib/src/datum_apis/vpc_attachment.rs`)

```
kind: VPCAttachment
group: networking.datumapis.com/v1alpha1

spec:
  connectorRef: {name}       # the iroh Connector this attachment binds
  vpcRef: {name}             # which gVPC to join
  mode: VPCOnly | DefaultRoute

status:
  conditions: [Bound, AddressAssigned, Ready, ...]
  assignedAddress: <IPv6 host address>
  advertisedPrefixes: [<CIDR>, ...]
  mtu: <int>
  routerEndpointId: <iroh EndpointId, z-base-32>
```

This mirrors `ConnectorAdvertisement`'s relationship to `Connector` — a new
binding object referencing the reusable `Connector` primitive, not a
replacement for it. `routerEndpointId` is populated once a galactic-side
router controller claims the attachment (a claim pattern, needed because
many remote clients per node must be distributed across router instances);
the client's accept handler allow-lists exactly that id.

**Not yet wired up**: `vpc join` currently takes `vpcRef`'s effects
(address/prefixes/mode/router identity) as explicit CLI flags rather than
polling this CRD's status — see §6. The type exists and compiles so the
contract is concrete, but nothing creates or watches real
`VPCAttachment` objects yet.

## 5. The galactic-side router (imagined component)

No galactic component exists today that terminates a remote client's
tunnel into a VPC — `galactic-gateway` is ingress-only (DSR L4LB),
`galactic-nat66` is outbound-only. This design assumes a new component,
tentatively `galactic-connect`, imagined with this contract so the CRD
above has a real consumer in mind:

- Watches `VPCAttachment` resources in `Bound` state, claims one (writing
  its own iroh `EndpointId` to `status.routerEndpointId`), allocates an
  address (reusing the ingress-sidecar's `DeriveGatewayAddress` pattern for
  collision-safe, non-tenant-IPAM addresses), and advertises it over BGP —
  the same VRF/`hostgw` mechanics the ingress-sidecar (`galactic-vrf`)
  already uses to make a non-CNI-attached endpoint reachable, including the
  easy-to-miss `NUD_PERMANENT` neighbor entry (`bpf_fib_lookup()` doesn't
  itself trigger NDP resolution).
- Own `BGPVRFInstance`/Argument per remote client rather than sharing the
  tenant's, per the return-path plan's precedent — many simultaneous remote
  clients per node must not collide in the 12-bit Argument space.
- Opens its own TUN device and dials the client by its iroh `EndpointId` on
  `IROH_VPC_ALPN` once claimed — no IP/port; iroh discovery resolves how to
  reach the client (published under its `Connector` status). It then pumps
  packets between the TUN device and the iroh stream using the same framing
  this repo implements (`lib/src/vpc/transport.rs`'s `pump` — shared by
  `VpcDialer`, used by the containerlab lab's mock router, which likewise
  dials by endpoint id alone).
- Likely a new binary rather than a mode of `galactic-router`, matching this
  codebase's split-by-failure-domain pattern (`galactic-gateway` /
  `galactic-router` / `galactic-nat66`).

This is scaffolding for design purposes, not a implementation plan for the
galactic repo — building it for real is out of scope here and depends on
where `VPCAttachment` (or its galactic-side analogue) actually lives, which
is a cross-repo API-ownership decision this design doesn't make
unilaterally.

## 6. Known limitations / follow-ups

- **No control-plane wiring yet**: `vpc join` takes flags, not a
  `VPCAttachment` watch. Wiring it up is the natural next step once a real
  router exists to populate the CRD's status.
- **`--router-ip` (DefaultRoute mode's anti-loop pin) is a simplification**:
  it pins one static host route so the tunnel's own iroh traffic isn't
  swallowed by the split-default routes. But iroh dials by `EndpointId` and
  reaches a peer over relays and/or multiple discovered direct paths that
  change over time, so a single static IP can't reliably cover the underlay.
  A production DefaultRoute mode needs to pin routes for the endpoint's
  *currently connected* relay/direct addresses and update them as they
  change (the labs use VpcOnly mode, which doesn't touch the default route,
  so they don't hit this).
- **No per-attachment key persistence**: each `vpc join` run generates a
  fresh iroh identity in memory (like `tunnel listen --endpoint` does before
  a tunnel exists). Once CRD-backed, this should follow `tunnel`'s
  `listen_key_for_tunnel`-style persistence so an attachment's iroh identity
  (and therefore its `Connector`) survives restarts.
- **MTU is a fixed conservative default**, not derived from iroh's actual
  per-path overhead budget.
- **Linux + macOS implemented; both exercised.** `create_tun_device` uses the
  cross-platform `tun` crate; `routing.rs` is OS-gated — iproute2 (`ip`) on
  Linux, `ifconfig`/`route` on macOS — and macOS `utun` names are auto-assigned
  and read back (the kernel rejects arbitrary names). The `tun` crate hides the
  macOS `utun` 4-byte protocol header, so the data plane is identical. Both are
  validated cross-machine (a Mac at home joining a VPC on a Linux VM over iroh).
  Windows (wintun) is not implemented.
- **macOS on-link source selection.** On macOS the connected route for the
  tunnel's own subnet is built with the utun's link-local as next hop, so the
  kernel may pick that link-local — not the client's VPC address — as the source
  for a destination *in that same subnet* (e.g. the router's own tunnel
  address). Reaching VPC members in other prefixes (via the explicit VPC-prefix
  route) is unaffected, and forcing the source (`ping6 -S <vpc-addr>`) works.
  Real members generally aren't in the client's own on-link subnet, but a client
  that must reach one should source from its VPC address explicitly; a cleaner
  fix (installing the on-link route as an interface route) is a follow-up.
- **Framing is stream + length-prefix, not QUIC datagrams** — simpler to get
  right first, but datagrams are a better long-term match for IP's
  best-effort delivery model (see §3).

## 7. Testing

See `deploy/containerlab/vpc/README.md`. Two labs, both driving a
`mock-galactic-router` fixture that stands in for §5's imagined component,
proving the data-plane mechanism (TUN creation, iroh accept/dial handshake,
framing, routing-mode installation) end-to-end without depending on anything
in the galactic repo:

- **`test-3region.sh`** — the repeatable full-mesh test: a 3-region VPC
  (mirroring galactic's dfw/sjc/iad model) with the router on it and the
  local device joining through the router, then a full-mesh ping matrix over
  all four devices. Self-contained on Docker, idempotent, non-zero exit on
  any failure. The router is a plain IPv6 L3 hub: kernel forwarding moves
  packets between the three regional segments and the tunnel TUN, while
  `mock-galactic-router` only pumps the tunnel — the same split a real
  galactic router has. Verified: all 12 ordered pairs reachable.
- **`vpc.clab.yaml`** — a minimal 2-node client/router walkthrough.

An addressing detail worth stating because it bit during bring-up: the
advertised VPC prefix must genuinely *cover* the addresses the client needs
to reach. Regional subnets `fd00:cafe:{a,b,c,100}::/64` differ in their third
16-bit group, so their covering aggregate is `fd00:cafe::/32`, not
`fd00:cafe::/48` (a `/48` fixes the third group). A prefix that doesn't cover
a destination simply doesn't match and the destination is unreachable — a
config error, not a routing-layer one. Routes into the VPC are plain `dev`
routes out the tunnel, as `wg-quick` installs AllowedIPs: with exactly one
peer on the interface (the router), every accepted packet goes to it anyway,
so no next-hop gateway is needed.

## 8. Cross-machine validation (Mac at home ↔ VM in a data center)

Validated end-to-end with the client on a bare-metal macOS laptop at home and
the VPC on a Linux VM in a data center, connected over the public internet —
the client dialed by iroh `EndpointId`, no ip/port anywhere.

```
                HOME                                        DATA-CENTER VM (Linux, dockerd)
┌──────────────────────────────────┐             ┌───────────────────────────────────────────────────────┐
│  MacBook (macOS)                 │             │    ┌─────────────────────────────────────────────────┐│
│   datum-connect vpc join         │             │    │ router container (mock-galactic-router)         ││
│   (iroh ACCEPT side)             │             │    │   IPv6 forwarding = on                          ││
│                                  │             │    │   mock-vpc0 (TUN)  fd00:cafe:1100::1            ││
│   utun8  fd00:cafe:1100::2/64    │             │    │        │  kernel-forwards between the tunnel    ││
│      │ route fd00:cafe::/32      │             │    │        │  TUN and the three region segments     ││
│      ▼   dev utun8               │             │    │   eth1 ─── eth2 ─── eth3                        ││
│   [TUN ⇄ iroh forwarder]         │             │    │   fd00:d0c:1{a,b,c}::ff  (router links)         ││
│      │                           │             │    └────┼───────┼───────┼────────────────────────────┘│
│      │  iroh/QUIC bi-stream      │             │         │docker │bridges│  fd00:d0c:1{a,b,c}::/64     │
│      │  ALPN datum-connect/vpc/0 │─────────────────────▶ │       │       │                             │
└──────┼───────────────────────────┘    ▲        │     ┌───┴──┐ ┌──┴───┐ ┌─┴────┐  region containers     │
       │      dialed by EndpointId      │        │     │region│ │region│ │region│  VPC addrs:            │
       └─────── (no ip/port — iroh ─────┘        │     │  -a  │ │  -b  │ │  -c  │  cafe:1a::1            │
               discovery + relays)               │     └──────┘ └──────┘ └──────┘  cafe:1b::1 cafe:1c::1 │
          PUBLIC  INTERNET                       └───────────────────────────────────────────────────────┘

VPC address space      = fd00:cafe::/32          reachable from the laptop ONLY through the iroh tunnel
docker "native" fabric = fd00:d0c:1{a,b,c}::/64  router⇄region links; the laptop has no route to these
```

Key properties this validated:

- **Only iroh crosses the internet.** The VPC prefix (`fd00:cafe::/32`) lives on
  the TUN devices; the laptop has no other route into it, so every laptop↔VPC
  packet rides the iroh tunnel.
- **Dial-by-identity.** The router dials the laptop's iroh `EndpointId` —
  discovery/relays resolve reachability; no IP or port is configured anywhere.
- **The router is a plain L3 hub.** `mock-galactic-router` only pumps its TUN;
  the Linux kernel forwards between the tunnel and the three region segments —
  the same split a real galactic router would have.
- **docker is invisible to the client.** The `fd00:d0c:*` links are only the
  router⇄region fabric; splitting that prefix from the VPC prefix keeps the
  client's traffic on the tunnel rather than a docker shortcut.

The run, across the three machines/roles (`deploy/containerlab/vpc/test-host-client.sh`):

On the data-center VM (docker) — stand up the containerized VPC:

```
% ./test-host-client.sh up
==> Tearing down containers/networks (host client, if running, must be stopped separately)
==> Creating networks
==> Starting region devices
==> Starting router (L3 hub) and attaching it to every regional segment

==> Containerized VPC is up.
```

On the Mac — join the VPC (creates the utun; dialed by id), then verify
client→VPC:

```
% nix build
% sudo env DATUM_CONNECT_DIR=/tmp/vpchost-datum DATUM_SESSION=lab \
    DATUM_CREDENTIALS_HELPER="$PWD/deploy/containerlab/vpc/fake-credentials-helper.sh" \
    DATUM_API_HOST=https://api.lab.invalid \
    ./result/bin/datum-connect --json vpc join --vpc lab-host \
    --address fd00:cafe:1100::2 --prefix-len 64 --mode vpc-only --vpc-prefix fd00:cafe::/32
{"address":"fd00:cafe:1100::2","bound_addrs":["0.0.0.0:60114","[::]:56325"],"endpoint_id":"9968ba066a6f01d0fec0f41e1a81a32ddd2af58def83178c4531b46539038eea","mode":"vpc-only","tun_name":"utun8","type":"vpc_ready","vpc":"lab-host"}

% deploy/containerlab/vpc/test-host-client.sh client-check
==> Waiting for the tunnel to settle (client -> router over iroh)
==> Reachability from the client into the VPC
PASS client -> region-a (fd00:cafe:1a::1)
PASS client -> region-b (fd00:cafe:1b::1)
PASS client -> region-c (fd00:cafe:1c::1)
PASS client -> router (fd00:cafe:1100::1)

PASS client reaches the whole VPC over the tunnel
```

Back on the VM — the router dials the Mac by its endpoint id and verifies
VPC→client:

```
% ./test-host-client.sh dial 9968ba066a6f01d0fec0f41e1a81a32ddd2af58def83178c4531b46539038eea
==> router: dialing the client by endpoint id (via iroh discovery)
==> Waiting for the tunnel to settle (region-a -> client over iroh, up to 90s)
==> Reachability from the VPC to the client (fd00:cafe:1100::2)
PASS region-a -> client (fd00:cafe:1100::2)
PASS region-b -> client (fd00:cafe:1100::2)
PASS region-c -> client (fd00:cafe:1100::2)

PASS VPC -> client reachable. Run './test-host-client.sh client-check' ON THE CLIENT for the client -> VPC direction.
```
