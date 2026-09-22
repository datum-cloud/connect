# `vpc` containerlab lab

Proves the `vpc` verb's data-plane mechanism end to end — TUN creation, the
iroh accept/dial handshake, packet framing, and routing-mode installation —
against a `mock-galactic-router` fixture that stands in for the imagined
galactic-side component (see `../../../design/vpc-attachment.md` §5 and §7).
It does **not** exercise any real galactic VRF/BGP/eBPF, and does not yet
talk to a `VPCAttachment` resource — see the design doc for what's
scaffolded ahead of the real control plane.

There are three labs here:

- **`test-3region.sh` — the automated, repeatable full-mesh test.** A 3-region
  VPC (mirroring galactic's dfw/sjc/iad model) with the router on it and the
  local device joining through the router, then a full-mesh ping matrix proving
  every device reaches every other. Self-contained on plain Docker (no
  containerlab, no root beyond Docker access), idempotent, exits non-zero on any
  failure. **Start here** — `./test-3region.sh`. Canonical containerlab form of
  the same topology: `vpc-3region.clab.yaml`.
- **`test-host-client.sh` — a bare-metal client joining the containerized VPC.**
  The client runs as a real process with a real TUN (needs your sudo), joining
  the VPC over iroh. The client can be on the same machine as the containers or
  on an entirely different machine/network (a laptop joining a VPC on a remote
  VM). See "The host-client test" below.
- **`vpc.clab.yaml` — the minimal 2-node walkthrough** below, for understanding
  the client/router handshake step by step by hand.

## The 3-region test

```bash
cd deploy/containerlab/vpc
./test-3region.sh          # build image if needed, stand up, verify, tear down
./test-3region.sh --keep   # leave it up afterwards to poke at
./test-3region.sh --down   # tear down a --keep run
```

Topology (all nodes run `connect-vpc-lab:latest`): a `router` acts as a plain
IPv6 L3 hub — it forwards (kernel forwarding) between three regional segments
(`fd00:cafe:{a,b,c}::/64`) and, over the iroh tunnel, the `local` device
(`fd00:cafe:100::2` on its `datum-vpc0` TUN). `mock-galactic-router` itself only
creates its tunnel TUN and pumps packets; the kernel does the forwarding — the
same division of labor a real galactic router has (its VRF/eBPF datapath
forwards; the userspace agent just moves tunnel packets). The VPC aggregate is
`fd00:cafe::/32` because it must cover all of `fd00:cafe:{a,b,c,100}::/64`, whose
third 16-bit group differs — a `/48` fixes that group and would exclude them.

Expected tail:

```
PASS local -> region-a (fd00:cafe:a::1)
...
PASS all devices can reach all other devices
```

The containerlab form (`vpc-3region.clab.yaml`) sets up the same nodes,
addressing, and regional links; `containerlab` needs root to deploy (supply it
yourself), then drive the app layer as `test-3region.sh` does — start the
client, note its endpoint id, start the router dialing it by id, ping.

## The host-client test

`test-host-client.sh` runs the client as a bare-metal process (a real TUN in a
real network namespace), joining the containerized VPC over iroh. The client can
be on the **same machine** as the containers, or on a **different machine and
network** entirely — a laptop joining a VPC on a remote VM. iroh dials the client
by EndpointId (no ip/port) either way.

Which command runs where:

- **VPC side (the docker host / VM)** — the only commands that touch docker:
  - `./test-host-client.sh up` — stand up the VPC; prints the client command.
  - `./test-host-client.sh dial <client-endpoint-id>` — drive the **router** to
    dial the client, then check the VPC→client direction. `dial` is *not* the
    client; it runs the router container.
  - `./test-host-client.sh down` — tear down.
- **Client side (this or any other machine)** — no docker:
  - the `datum-connect … vpc join …` command that `up` prints (run under sudo;
    it creates the TUN). On a remote client, copy the `datum-connect` binary and
    `fake-credentials-helper.sh` over first, and build `datum-connect` for that
    machine's OS/arch.
  - `./test-host-client.sh client-check` — ping the whole VPC from the client
    (client→VPC direction), no docker needed.

Same-machine run: do all of the above on one host. Cross-machine run (laptop ↔
remote VM):

```
[VM]     ./test-host-client.sh up                 # note the client command it prints
[laptop] sudo env ... datum-connect ... vpc join  # from up's output; note the endpoint id
[laptop] ./test-host-client.sh client-check        # client -> VPC
[VM]     ./test-host-client.sh dial <endpoint-id>  # router dials client; VPC -> client
[VM]     ./test-host-client.sh down                # Ctrl+C the client on the laptop too
```

Only one client may hold the VPC address (`fd00:cafe:1100::2`) at a time — stop
any client already running (e.g. a same-machine one from a prior test) before
starting another, or the second will collide.

## Topology

Two nodes, `client` and `router`, both running the same image (the built
`datum-connect`/`mock-galactic-router` Rust binaries and the `datumctl-connect`
Go plugin binary), reachable over containerlab's management network — no
extra data links are needed since the "VPC" traffic runs *inside* the iroh
tunnel, not over a separate wire.

`client` runs `datumctl-connect vpc join` — the accept side, exactly as in
production (see the design doc for why the client always starts first).
`router` runs `mock-galactic-router` — the dial side, given the client's
iroh endpoint id and address directly instead of discovering them via a
claimed `VPCAttachment`.

## Privileges

Creating a TUN device and managing routes needs `CAP_NET_ADMIN`. The
topology grants that to both nodes via `cap-add` and binds in
`/dev/net/tun`; nothing in the image, the binaries, or this README invokes
`sudo` or otherwise tries to elevate itself. If a command below fails with
a permission error, that means the *host* you're running `docker`/
`containerlab` on needs it (e.g. your user isn't in the `docker` group, or
containerlab itself needs root to manage network namespaces) — supply that
yourself; these tools deliberately fail with a clear message instead of
guessing at how to get root.

## 1. Build the image

Build context must be the **repo root**, not this directory, since the
Dockerfile needs both `connect-lib/` and `connect-plugin/`:

```bash
cd /path/to/connect
docker build -f deploy/containerlab/vpc/Dockerfile -t connect-vpc-lab:latest .
```

## 2. Deploy the lab

```bash
cd deploy/containerlab/vpc
containerlab deploy -t vpc.clab.yaml
```

## 3. Start the client

The client always starts first — it doesn't need to know anything about
the router yet:

```bash
docker exec -d clab-vpc-attachment-client sh -c \
  'datumctl-connect vpc join --vpc lab-vpc --address fd00:1::2 --prefix-len 120 > /tmp/client.log 2>&1'
```

Wait a couple seconds, then read its output:

```bash
docker exec clab-vpc-attachment-client cat /tmp/client.log
```

You should see something like (verified output, the id will differ per run):

```
  ⚠ No --router-id set — accepting any dialer (trust-on-first-connect). This is only appropriate for lab/dev use; see design/vpc-attachment.md.
VPC attachment ready: lab-vpc at fd00:1::2 via datum-vpc0 (mode vpc-only)
Endpoint ID: b123d11e1359bd3bfadca82faad93697bea00cdb7d2bbcd396a0b428ab44a554
Listening on: 0.0.0.0:40295, [::]:37541
Press Ctrl+C to stop...
```

Note the **endpoint ID** — that's all the router needs. iroh resolves how to
reach it via discovery; no ip/port. (`Listening on` is just iroh's local
wildcard bind, printed for reference.)

## 4. Start the router

```bash
docker exec -d clab-vpc-attachment-router sh -c \
  'mock-galactic-router \
     --peer-id <endpoint id from step 3> \
     --address fd00:1::1 --prefix-len 120 \
     > /tmp/router.log 2>&1'
```

The router dials the client by endpoint id alone (both ends reach iroh
discovery + relays over normal outbound internet). `mock-galactic-router`
also accepts an optional `--peer-addr <ip:port>` to pin a direct address and
bypass discovery — only useful for an offline/same-host lab.

```bash
docker exec clab-vpc-attachment-router cat /tmp/router.log
```

You should see the router print its own endpoint id and confirm it's
dialing the client — it doesn't print anything further once connected (see
`connect_lib::vpc::VpcDialer::dial_and_pump`, which just starts pumping
silently); the ping in step 5 is the real confirmation the connection
succeeded.

## 5. Prove it: ping across the tunnel

Both ends configured the same `/120` prefix on their own TUN device, so
each already has an on-link route to the other via the interface `ip addr
add` created — no extra route needed for this basic check:

```bash
docker exec clab-vpc-attachment-client ping -c4 fd00:1::1
docker exec clab-vpc-attachment-router ping -c4 fd00:1::2
```

A successful round trip here means: the TUN devices were created and
addressed correctly, the iroh accept/dial handshake completed, and IP
packets are being framed, sent over the iroh stream, and unframed
correctly in both directions.

## Cleanup

```bash
containerlab destroy -t vpc.clab.yaml
```

## What this doesn't prove

- **Routing modes beyond the on-link check above.** Testing `--mode
  default-route` meaningfully needs a third "internet-side" destination to
  route away from and a real default gateway to preserve — this 2-node lab
  doesn't have one. Testing `--vpc-prefix` in `vpc-only` mode needs a prefix
  that *isn't* the on-link one above (the on-link route already exists from
  address assignment; adding the identical route again with `ip route add`
  fails).
- **Anything about the real galactic component** — VRF/BGP/eBPF wiring,
  address allocation, claiming a `VPCAttachment`. See
  `../../../design/vpc-attachment.md` §5.
- **Non-Linux TUN creation** (macOS `utun`, Windows wintun) — untested
  anywhere so far, containerlab included.
