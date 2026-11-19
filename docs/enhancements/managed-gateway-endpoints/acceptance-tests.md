# Acceptance tests

These are proposed release checks for the [design](README.md). This documentation
change does not implement or run them.

## Setup

Use two customer projects, a separate Connect service-provider project, two
Locations in the same metro, another metro, and two cells.
Exercise the real DNS, certificate, distribution, and Galactic integrations.
Keep another tenant connected to the same listeners during failure tests.

Record component versions, object UIDs, applied configuration versions, public
certificate fingerprints, DNS answers, and packet results. Never record keys or
bearer credentials. A TLS handshake alone does not prove VPC connectivity.

## Names and authorization

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
- Change cells and verify that routing and newly issued grants agree. Do not
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
