# Acceptance tests

These are release checks for the [design](README.md). Local implementation tests
cover parts of the contract; they do not replace deployed packet qualification.

## Setup

Use two customer projects, a separate Connect service-provider project, two
Locations in the same metro, another metro, and two cells with separate control
planes. Include multiple serving replicas in at least one control plane.
Exercise the real DNS, certificate, distribution, and Galactic integrations.
Keep another tenant connected to the same listeners during failure tests.

Record component versions, object UIDs, applied configuration versions, public
certificate fingerprints, DNS answers, and packet results. Never record keys or
bearer credentials. A TLS handshake alone does not prove VPC connectivity.

## Names and authorization

- Managed registration specs and public grant/authority messages contain named
  references, no authored UID fields or customer Project field. Check distributed
  registration, Secret and policy metadata for identity UID labels/annotations;
  none may replace the removed fields. Kubernetes metadata.uid remains internal.
- Recreate a VPC or service with the same name. Old authorization receipts must
  fail, including refresh and retire against a replacement service. Recreate an
  instance or reacquire its Lease: an acknowledgment preceding either incarnation
  must not make the endpoint ready. Missing acquisition timestamps fail closed.
- Recreate a delivered object with identical content and a new metadata UID.
  Private cleanup receipts must reject its adoption/deletion. An uncertain initial
  create may be adopted only after exact desired-content verification.
- Internal endpoint and cleanup records, the managed `DNSZone`, routing and
  challenge `DNSRecordSet` resources, and `TLSCertificate` requests live in the
  Connect service-provider project. Customer credentials cannot modify them. Private keys
  remain outside both customer and service-provider Project control planes.
- Customer project deletion leaves service-project cleanup records available.
  Service-project retirement waits for its endpoints and cleanup work to finish.

- Two Locations in one metro produce one endpoint and certificate. Controller
  retries and restarts do not create duplicates.
- Identical gateway names in different projects receive separate endpoints.
  Deleting and recreating a gateway does not recover its old hostname.
- Unknown metro membership blocks provisioning. A temporary Location failure
  preserves the reservation; removing one same-metro placement preserves access.
- Ordinary tenants cannot request certificates for the managed domain or modify
  service-owned reservations, registrations, or delivery targets.
- A valid credential cannot access another gateway by changing SNI, HTTP authority,
  or the VPC selector. Test each transport, including multiple HTTP/2 requests
  sharing a connection.

## Placement and local acknowledgments

- Keep metro and cell assignments in Connect's service-provider Project. Delivered
  `MASQUEEndpoint` specs have no `cell` or `metro` fields. Galactic does not require
  those fields to accept an otherwise valid local registration.
- Verify distribution targeting and credentials reach only the selected control
  plane. A misplaced registration must be prevented by that boundary, not by a
  redundant field check inside Galactic. Read readiness from the selected API.
- When multiple providers are independently selectable in one control plane,
  verify the local provider reference selects only the intended provider. When
  selection is implicit, do not require a redundant provider field.
- With multiple serving replicas, delay one replica's apply acknowledgment. The
  endpoint stays unready even if another replica reports success. On removal,
  require forwarding-stop confirmation from every relevant replica.
- Resolve each `instanceName` locally against current membership and its Lease.
  A same-named instance in another control plane cannot satisfy readiness.

## Multiple networks on one connection

- Create a gateway without `networkRef`. Bind two differently named Networks with
  explicit `gatewayRef`, `connectorRef` and `networkRef`. Authorize both through
  `ConnectConnectionPolicy.networkRefs`. Users supply no UIDs, cell IDs or VPC IDs.
- For each H3 and H2 case, record one actual accepted QUIC/TLS connection identity
  and two distinct CONNECT-IP stream IDs. Exchange packets on both simultaneously.
  Merely opening two clients or sharing a pool object is not sufficient evidence.
- A third network and a credential replay with a changed VPC selector are denied.
  A gateway-only policy with no network list remains denied after migration.
- Revoke one binding while the other transfers packets on the same connection.
  Recreate the revoked binding and obtain a fresh independently scoped grant.
- Delete and recreate one Network or VPC under the same name. Old grants and
  bindings must not follow the replacement UID. Reapprove the replacement through
  a new binding; shared DNS, certificate, listener and sibling remain unchanged.
- Expire/refresh one stream credential without closing its sibling. Fail the
  physical connection; both desired attachments independently reauthorize and
  reconnect onto one replacement transport within the same security context.
- Rotate the shared certificate, including a shorter-lived replacement. A new
  TLS connection is needed to observe the new fingerprint; a preexisting TLS
  session is not evidence of the replacement. Disable the endpoint and verify
  all of its streams stop while another tenant remains usable.
- Reject overlapping device-local routes. Separate server-side VPC streams do
  not establish overlapping-network support on the client operating system.

## Certificates and listeners

- DNS-01 uses the exact returned challenge CNAME and completes without an HTTP
  challenge listener. Missing or incorrect delegation reports a useful error.
- Wrong Secret ownership, mismatched keys, incorrect names, and expired
  certificates prevent activation. Private keys never reach project APIs.
- Delivery reaches only selected cells. Readiness waits for every instance that
  may receive traffic to apply the expected registration and certificate.
- Renewal works without a process restart. Same-expiry replacements and emergency
  rekeys with shorter validity also reach the listener.
- An invalid update or failed renewal for one endpoint does not break another
  tenant. A valid existing certificate may keep serving while renewal retries.
- External clients verify WebPKI and exchange packets with the VPC over both
  HTTP/3 and HTTP/2. Block UDP to test fallback; TLS and authorization errors
  must not trigger fallback.

## Failure, recovery, and release

- Stop controllers after writes but before responses. Retry without duplicate
  names or grants; reject delayed updates from an older configuration.
- Interrupt project API access, DNS, issuance, distribution, and cell access.
  Report the failing dependency and do not mistake an outage for deletion.
- Remove selected-cell reachability for one network. That binding becomes
  unavailable without moving the endpoint or interrupting other bindings. Do not
  claim transparent roaming or preserved allocations.
- Revoke a binding or gateway while traffic is active. Measure admission denial,
  forwarding cutoff, and route withdrawal separately from DNS removal.
- Delete a gateway, namespace, or project. Confirm removal of routing records,
  registrations, delivered keys, and issuance requests. Leave shared providers,
  the shared DNS zone, unrelated records/endpoints, certificate-service anchors,
  and Galactic allocation
  tombstones intact.
- Lose a cell during deletion. Keep cleanup pending until removal is confirmed or
  the agreed permanent-loss recovery procedure completes.
- Restore backed-up records while old callbacks replay. A revoked endpoint must
  stay revoked. Cached DNS must not give access to a replacement gateway.
- Roll out and roll back with active connections. Keep renewal and cleanup running
  when new provisioning is disabled; drain before using incompatible listeners.

## Operational checks

Measure certificate lifetime margins, registration size, issuance throughput,
probe load, renewal delay, and cleanup time at expected scale. Agree on alerting,
revocation deadlines, and recovery ownership before production.

Connect, Galactic, certificates, and infra owners should record results for their
boundaries, including skipped checks and environment limits. Unit tests and
manifest rendering do not replace the end-to-end packet and cleanup checks.

Keep three evidence sets separate: Rust client loopback tests with actual H3/H2
connections, Galactic real-authority tests with a fake packet backend, and live
DNS/ACME/Karmada/cell/operating-system packet tests. Record skipped checks and
artifact digests. The first two do not qualify the last.
