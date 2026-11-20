# Staging managed gateway qualification

This runner uses the production Rust transport pool, the real credential API,
normal public TLS trust, and ICMPv6 echo traffic inside CONNECT-IP. It creates no
Kubernetes resources, routes, interfaces, certificates, or policy. Infra is the
sole staging configuration writer. Never use production credentials or endpoints.

## Prerequisites

Use the exact published Connect image/source and record the Galactic, Certificates
and Infra source/image digests. Infra must first establish the public TCP/UDP 443
frontend, DNS delegation, real certificate issuance, verified broker backend TLS,
and the authenticated probe below. Do not enable provisioning with a fake probe.

Coordinate two nonoverlapping allocator-assigned VPCs, two explicitly permitted
bindings and a third existing binding excluded by policy. Each permitted VPC needs
a real ICMPv6 responder and return routing to its delegated /96. Network/VPC
recreation must use the allocator again; never fabricate allocation identifiers.
The signed-in client security context must be authorized for its bindings and for
`create connectnetworkbindings/connection-credentials`. Use a short-lived bearer
file, mode 0600, outside the repository. Do not record tokens or descriptors.

Create a private JSON file with these keys (all are required):

```json
{
  "credentialUrls": ["https://API/…/connectnetworkbindings/managed-e2e-a/connection-credentials", "https://API/…/connectnetworkbindings/managed-e2e-b/connection-credentials"],
  "deniedCredentialUrl": "https://API/…/connectnetworkbindings/managed-e2e-denied/connection-credentials",
  "tokenFile": "/secure/staging-bearer",
  "targets": ["ALLOCATED_IPV6_RESPONDER_A", "ALLOCATED_IPV6_RESPONDER_B"],
  "protocol": "h3"
}
```

Replace the illustrative URLs with the full path documented below. Targets must
fall inside the descriptors' authorized routes. Run from the repository:

```sh
cd connect-lib
cargo run -p datum-connect-daemon --example managed-gateway-e2e -- /secure/config.json
```

Run separately with `protocol` set to `h3` and `h2`, restoring the isolated fixtures
between runs. The runner first proves two distinct stream IDs share one actual
transport object, checks exact provider route/prefix capsules, and validates
nonce-bearing ICMPv6 replies including pseudoheader checksum. It then tests
cross-VPC credential replay and explicit third-binding Forbidden, checking both
permitted siblings still forward. No mocks run in this executable.

At each prompt, Infra performs the named operation and observes reconciliation;
type the exact checkpoint only afterward:

- `binding-a-revoked`: revoke only A, wait for authority refresh; runner checks old
  stream/reconnect denial and B's continued packets on its original stream.
- `binding-a-restored`: restore authorization using a new activation/connector as
  required; runner remints A and checks transport reuse with the surviving B.
- `network-a-recreated`: replace A's Network/VPC incarnation, leaving its old
  binding. Old packets/reconnect and credential mint must fail; B must survive.
- `binding-a-rebound`: explicitly recreate A's binding for the new network. If its
  allocated responder changed, update `targets` in the JSON before confirming.
- `certificate-rotated`: rotate through the real issuance pipeline, wait for the
  trusted probe's exact new digest and all-replica acknowledgments. Runner opens a
  fresh pool/PKIX TLS connection and proves both VPCs again. Its output alone does
  not prove the leaf changed; retain the independent authenticated probe report.
- `endpoint-disabled`: disable the gateway, wait for every relevant instance's
  stopped acknowledgment. Runner checks packet/reconnect denial. Retain the
  authoritative stop evidence separately; timeout alone is not that evidence.

Negative stream assertions require an actual HTTP 401/403 from the peer; TLS,
connectivity, plan, and 5xx failures are inconclusive, not authorization denial.
The third binding must return HTTP 403, not merely fail to mint. Both legitimate
streams are reprobed afterward. Unit tests guard this distinction.

JSON lines retain actual nonce-bearing request/reply packet hex, stream IDs and
process-local client transport IDs, never credentials. These transport IDs identify
the live Rust transport object, not a server-issued identifier or a portable ID
across process restarts. Correlate timestamps/stream IDs with provider-side
connection evidence when collecting the staging report; do not label client IDs
as independently observed server accepts. A nonzero exit
is a failed/incomplete run, even if earlier phases passed. Keep stderr and source
SHAs alongside stdout. Stream Drop cancels attachments on every error path; the
failure message requires Infra's disable/cleanup rather than silently leaving
fixtures active. The runner never removes control-plane resources itself. After
success **or failure**, use Infra's `check-managed-endpoint cleaned` with the
operator-bound selected-cell kubeconfig and retained receipt inventory. Runner
completion is not proof of cleanup. Do not delete ledgers, fences or tombstones.

This is real tunneled traffic, not OS adapter qualification: no TUN/device route
is installed by this runner. OS integration and overlapping device route contexts
remain separate gates. Local `cargo test --example managed-gateway-e2e` only checks
packet construction; local pooling/server fixtures are not staging evidence.

## Trusted endpoint probe

The controller image also includes `/endpoint-probe`. Run a separate Deployment
at a vantage that can reach the actual public frontend, with:

```text
--listen-address=:8443
--tls-cert=/tls/tls.crt
--tls-key=/tls/tls.key
--client-ca=/tls/client-ca.crt
--endpoint-project-kubeconfig=/readers/project.yaml
--endpoint-namespace=default
--endpoint-runtime-namespace=masque-system
--endpoint-domain=connect.datum-staging.net
--endpoint-config=/config/config.json
```

Use a dedicated client CA issuing only the controller's probe client identity.
Serving certificates must have the probe Service DNS SAN. Configure the controller
with `--endpoint-probe-ca`, `--endpoint-probe-client-cert`, and
`--endpoint-probe-client-key`; all three are mandatory when `probeURL` is set.
Set `probeURL` to `https://SERVICE:8443/endpoints`. Do not expose this service
through the public credential route. NetworkPolicy should limit callers and allow
the probe's DNS, selected API and public TCP/UDP 443 egress.

Reuse the frozen capacity/cells JSON, but mount **only read credentials**. The
probe reads ConnectEndpoint from the explicit service Project, MASQUEEndpoint and
Lease by name, and EdgeInstances in the runtime namespace. No Secret access,
grant writes, Karmada writes or customer Project permissions are needed. The
probe does not use any grantKubeconfig paths in that JSON.

`GET /endpoints/{runtimeNamespace}/{reservationName}` requires mTLS. It checks
Active/not deleting, bounded domain, exact configured capacity, and every current
instance/Lease through the selected API. It resolves public CNAME/address records,
opens fresh normal-PKIX H2 and H3 connections, checks the exact leaf DER digest,
and requests `/.well-known/masque/ip/*/*/` without credentials. Galactic resolves
the live endpoint before rejecting this non-CONNECT request: expected H2 400 and
H3 405; disabled/unknown 421 fails. It then rereads reservation identity/revision
and all instance acknowledgments before returning the existing ProbeReport.

This checks public TLS/protocol endpoint reachability, not authorized packets.
No circular grant mint is needed to establish endpoint readiness. The packet
runner independently qualifies per-binding authorization and forwarding.

## Credential frontend route

Forward POST without rewriting this complete path or stripping Authorization:

```text
/apis/resourcemanager.miloapis.com/v1alpha1/projects/{project}/control-plane/apis/connect.datumapis.com/v1alpha1/namespaces/{namespace}/connectnetworkbindings/{binding}/connection-credentials
```

Anchored HTTPRoute RegularExpression (POST method match also required):

```text
^/apis/resourcemanager\.miloapis\.com/v1alpha1/projects/[a-z0-9][a-z0-9.-]*/control-plane/apis/connect\.datumapis\.com/v1alpha1/namespaces/[a-z0-9][a-z0-9-]*/connectnetworkbindings/[a-z0-9][a-z0-9.-]*/connection-credentials$
```

The broker independently applies strict Kubernetes name validation, caller bearer
SSAR, and fresh policy/binding checks. Route only this suffix to the broker Service;
preserve Milo's catch-all. Require BackendTLSPolicy with the broker serving SAN and
trusted CA, and a narrow ReferenceGrant for cross-namespace routing. Never trust
forwarded identity headers or enable plaintext backend fallback. Verify an
unauthenticated POST is Forbidden, unrelated API paths still reach Milo, and
valid credentials remain no-store. Public route installation belongs to Infra.
