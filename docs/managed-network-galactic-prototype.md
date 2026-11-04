# Managed-network Galactic prototype

This prototype adds an implementation-neutral logical gateway contract while
leaving the preview iroh gateway on `contractVersion: legacy-v1`. New native
provider gateways explicitly set `managed-network-v1`; transport is never
inferred from legacy endpoint fields. The logical gateway does not name
Galactic, a pod, a workload image, a credential, a VPC selector, or an endpoint.

## Ownership and trust boundaries

- A user owns `ConnectGateway`, `ConnectConnectionPolicy`, and
  `ConnectNetworkBinding` intent in one project.
- The Connect controller expands the gateway's Location selector into owned
  `ConnectGatewayPlacement` objects. The parent status contains three counts
  and exactly four aggregate conditions; per-location assignment stays on the
  placement.
- Policy gateway and subject selectors accept only positive `In` and `Exists`
  requirements on protected `policy.connect.datum.net/*` labels. The prototype
  subject mechanism is a protected Connector classification. Production must
  replace or supplement it with trusted IAM group membership.
- Bindings do not carry `policyRefs`. Every applicable policy is selected from
  the Connector's protected labels and composes additively over default deny.
- `access.permission: Network` is the prototype service-level permission. Its
  concrete IPv6 destination is read from the referenced Network's authoritative
  `status.ipam.ipv6Prefix`; users never enter a CIDR in a gateway or policy.
- The sensitive broker exposes only
  `POST /connectnetworkbindings/{name}/connection-credentials`. It authenticates
  the daemon, re-resolves binding policy, and calls a provider-specific issuer
  behind an interface. Responses are `no-store`; credentials have redacted
  string/debug representations and are never persisted in CRD status.
- Galactic's authority remains the owner of connector UUIDs, retained `/96`
  allocations, VPC selectors, grant revisions, and bearer credentials. A
  staging issuer must broker the existing administrative workflow rather than
  teaching the Connect controller to write Galactic grant records.
- The daemon consumes the versioned `masque.connect.datum.net/v1` descriptor.
  It requires WebPKI, `/96`, exact route equality, and MTU 1280 before calling
  the local networking activator. It chooses the first host `/128` in the `/96`.

## Session behavior

The dedicated adapter tries HTTP/3 first and permits HTTP/2 only after an H3
connectivity failure. HTTP 401 remints once, 403 waits for a binding change, 503
uses bounded backoff, TLS identity failure is terminal, and any prefix or route
mismatch fails closed without interface activation. A policy revision change
requires a new descriptor. A different placement is a new attachment and may
receive a different `/96`; this prototype makes no roaming guarantee.

The daemon runtime now mints a descriptor after a managed binding becomes
Ready, establishes WebPKI-authenticated CONNECT-IP over HTTP/3, and falls back
to HTTP/2 Extended CONNECT only when the HTTP/3 path has a connectivity
failure. It parses Galactic's delegated `/96` and route capsules, verifies
exact equality with the descriptor, selects the first host `/128`, and creates
the native interface only after verification. Packets are then bridged between
the native adapter and HTTP Datagrams or HTTP/2 DATAGRAM capsules. A 401 causes
one remint; application responses and TLS or plan failures never trigger a
transport fallback. The legacy iroh attachment remains selected only by the
legacy contract.

## Local validation

```sh
cd connect-controller
GOCACHE=/private/tmp/connect-managed-go-cache go test ./...
make deploy-render

cd ../connect-lib
PATH="$HOME/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin:$PATH" \
  CARGO_TARGET_DIR=/private/tmp/connect-managed-cargo-target \
  cargo test --locked -p datum-connect-daemon galactic_masque --lib
```

See [the example resources](examples/managed-network-galactic.yaml). Placement
objects are intentionally absent because the controller owns them.

