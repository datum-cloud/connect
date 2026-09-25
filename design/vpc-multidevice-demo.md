# Multi-device VPC demo with router-allocated IPv6 addresses

Status: **Implemented** (phases 1–3 + lab/doc updates; pending e2e validation)
Related: `design/vpc-attachment.md`, branch `vpc-894`

## Context

Today `datumctl connect vpc join` (scaffolding on branch `vpc-894`) lets **one**
device join a gVPC. Two things make it single-device:

1. **Addresses are hand-picked.** `--address` is a *required* flag with no
   uniqueness check (`connect-plugin/vpc/join/main.go:56,65`,
   `connect-lib/bin/src/vpc.rs:71`). Two devices copying the documented example
   both take `fd00:cafe:...::2`.
2. **The mock router serves exactly one client** — a single `--peer-id`, one
   TUN, one `pump` (`connect-lib/mock-galactic-router/src/main.rs`). The
   single-peer collapse is baked in (`VpcAcceptHandler` allows one router;
   `install_routes` is a mode toggle "since there is exactly one peer").

The design already anticipates N devices with router-side address allocation:
the imagined `galactic-connect` router "allocates an address … and advertises
it" (`design/vpc-attachment.md` §5), and `VPCAttachmentStatus` already reserves
`assignedAddress` / `advertisedPrefixes` for exactly this.

**Goal:** make 2+ devices join one gVPC in a repeatable demo, with each device's
IPv6 address **allocated and handed out by the router** over the iroh stream —
the wire analogue of the future CRD `assignedAddress` flow. Deliverables:
(1) a repeatable containerlab N-client lab, and (2) a two-real-laptop runbook.

## Approach

**Wire protocol (one code path):** the dialer (router) sends exactly one
`Assignment` control frame as the first framed message on the stream, then raw
packets; the accepter (client) reads that first frame, configures its interface
from it, then pumps. This matches the length-prefixed framing already in
`pump` (position disambiguates — no type tag). Bump `IROH_VPC_ALPN` to
`datum-connect/vpc/1` to mark the wire change (both ends live in this repo; the
verb is pre-release).

```
Assignment { address: Ipv6Addr, prefix_len: u8, vpc_prefixes: Vec<String> }
  → serialized as JSON inside one u16-length-prefixed frame
  (mirrors VPCAttachmentStatus.assignedAddress + advertisedPrefixes)
```

The client no longer needs `--address` / `--prefix-len` / `--vpc-prefix`; the
router supplies all three. `--mode`, `--mtu`, `--tun-name`, `--router-id`,
`--router-ip` stay client-side (they're local routing choices, not assigned).

### 1. Shared framing + Assignment — `connect-lib/lib/src/vpc/transport.rs`

- Extract the u16-length framing already inside `pump` into
  `pub(crate)`/`pub` helpers `write_frame(w, &[u8])` / `read_frame(r) ->
  Vec<u8>`, and rewrite `pump`'s two loops to call them (keeps the existing,
  tested behavior — the round-trip test stays green).
- Add `Assignment` (serde) + `send_assignment(w, &Assignment)` /
  `recv_assignment(r) -> Assignment` built on those helpers.
- `VpcDialer`: add `dial_and_send_assignment(...)` that opens the bi-stream,
  `send_assignment` first, then hands the stream halves back to the caller (the
  router needs the raw halves for its N:1 mux — see §3), rather than calling the
  1:1 `pump` itself.
- `VpcAcceptHandler`: gains an `on_assign` callback (an
  `Arc<dyn Fn(Assignment) -> BoxFuture<Result<()>>>`). In `accept`, after
  `accept_bi`, `recv_assignment`, run `on_assign` (which configures the
  interface + routes and reports the address back to `run_join`), **then**
  `pump`. Configuration must complete before `pump` delivers inbound packets, so
  the kernel accepts them.
- Extend the unit test module: `send_assignment`/`recv_assignment` round-trip,
  and pump-after-assignment on the same stream.

### 2. Client `vpc join` — Rust + Go

- `connect-lib/bin/src/vpc.rs` (`run_join`): drop `address`/`prefix_len`/
  `vpc_prefix` from `JoinArgs`. Create the TUN **unaddressed**, bind
  `VpcListener` with an `on_assign` closure that calls
  `vpc_configure_interface` + `vpc_install_routes(mode, assignment.vpc_prefixes,
  router_ip)` and sends the assignment to `run_join` via a `oneshot`. `run_join`
  waits on that oneshot, then emits `vpc_ready` carrying the **router-assigned**
  address (the JSON shape at `vpc.rs:108-120` is unchanged; `address` is now the
  assigned one). If no router connects, the Go supervisor's existing 2-min
  startup timeout applies.
- `connect-lib/bin/src/main.rs`: remove the three dropped flags from the `vpc
  join` arg struct/handler (~main.rs:196-240).
- `connect-plugin/vpc/join/main.go`: remove `--address` (and its
  `MarkFlagRequired`), `--prefix-len`, `--vpc-prefix`, and the code that
  forwards them (`main.go:56-66,89-106`). `VpcReady.Address` already renders the
  assigned address (`main.go:159-161`).

### 3. Router `mock-galactic-router` — N clients, allocate + demux

Rewrite `connect-lib/mock-galactic-router/src/main.rs` from one-peer/one-pump to
one shared TUN fanning out to N clients:

- Flags: `--peer-id` repeatable (`Vec<String>`); add `--pool <CIDR>` (client
  address pool, e.g. `fd00:cafe:1100::/64`), keep `--address` as the router's
  own pool address (e.g. `::1`), add `--advertise <CIDR>` repeatable (the
  `vpc_prefixes` sent to clients, e.g. `fd00:cafe::/32`).
- Allocate sequentially from `--pool` (`::2, ::3, …`) as peers are dialed; keep
  a `HashMap<Ipv6Addr, mpsc::Sender<Vec<u8>>>` (client addr → its stream).
- One TUN-reader task parses each outbound packet's IPv6 **destination** (bytes
  24..40) and routes it to the matching client's sender (unknown dst dropped).
  Per-client task: `dial_and_send_assignment(Assignment{addr, prefix_len,
  vpc_prefixes})`, then loop: drain its mpsc → `write_frame` to the client
  stream; and `read_frame` from the client stream → write to the shared TUN
  writer (behind a `Mutex`). Reuses §1's exported `write_frame`/`read_frame`, so
  there's still exactly one framing implementation.
- Client↔client works via the shared TUN: the pool `/64` is on-link (NOARP TUN),
  so the kernel forwards A→B back out the TUN and the demux delivers it to B —
  no extra router logic. (macOS same-subnet source-selection quirk carries over;
  clients use `ping6 -S`, exactly as the current labs already do — `design/vpc-
  attachment.md` §6.)

### 4. Labs + runbook

- **New `deploy/containerlab/vpc/test-multiclient.sh`** (modeled on
  `test-3region.sh`): 3 regions + router + **two** client containers; router
  dials both peer-ids; `check` runs a full-mesh ping matrix over all
  four+router including **A↔B**, non-zero exit on any failure. Add a
  `*-multiclient.clab.yaml` if the topology can't be reused.
- **Update `test-host-client.sh`** so `dial` accepts multiple peer-ids (dial N
  bare-metal laptops), and drop `--address` from the printed `vpc join` command.
- **Update `design/vpc-attachment.md`**: revise §8's cross-machine runbook to
  two laptops each running `vpc join` (no `--address`), the VM router dialing
  both endpoint ids, and an A↔B check; note router-allocated addressing in §1/§4
  and that `Assignment` is the on-wire shape of the CRD's `assignedAddress` /
  `advertisedPrefixes`. Update `README.md` if it shows `--address`.

## Files

| File | Change |
|---|---|
| `connect-lib/lib/src/vpc/transport.rs` | `Assignment`, `write_frame`/`read_frame`, `send/recv_assignment`, `on_assign` in accept handler, dialer sends assignment; ALPN → `/vpc/1`; tests |
| `connect-lib/lib/src/vpc/mod.rs` | thread `on_assign` through `VpcListener::bind`; re-export `Assignment` |
| `connect-lib/lib/src/lib.rs` | re-export `Assignment` (near line 34-37) |
| `connect-lib/bin/src/vpc.rs` | deferred configure; drop address/prefix/vpc-prefix args; emit assigned `vpc_ready` |
| `connect-lib/bin/src/main.rs` | drop the three `vpc join` flags |
| `connect-lib/mock-galactic-router/src/main.rs` | N-client dial + pool allocation + dst-demux mux |
| `connect-plugin/vpc/join/main.go` | drop `--address`/`--prefix-len`/`--vpc-prefix` |
| `deploy/containerlab/vpc/test-multiclient.sh` (+ clab yaml) | new 2-client repeatable lab |
| `deploy/containerlab/vpc/test-host-client.sh` | multi-peer `dial`; no `--address` |
| `design/vpc-attachment.md`, `README.md` | runbook + doc updates |

## Verification

1. **Unit:** `cd connect-lib && cargo test` — new transport tests
   (assignment round-trip, pump-after-assignment) plus the existing pump test.
2. **Build:** `task build` (both binaries).
3. **Containerlab e2e (repeatable):**
   `deploy/containerlab/vpc/test-multiclient.sh up`, then start the two
   `vpc join` clients it prints (each under `sudo`, no `--address`), then
   `... client-check` — expect a PASS matrix including **A↔B**, **A↔regions**,
   **B↔regions**; the script exits non-zero on any miss.
4. **Two real laptops:** follow the revised `design/vpc-attachment.md` §8
   runbook — both laptops `vpc join` one VPC on a remote VM, the VM router
   dials both endpoint ids, verify laptop-A ↔ laptop-B and each ↔ the VPC.
5. **No single-client regression:** the single-client `test-3region.sh` /
   `test-host-client.sh` still pass on the new router-allocated path.
