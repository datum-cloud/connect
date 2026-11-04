# Staging managed-network validation — 2026-11-04

Discovery was performed read-only on 2026-11-04 (America/Chicago).

| Item | Observed result |
| --- | --- |
| Cell / Location | `us-central-1`; Location Ready, region `us-central-1`, city code `DFW` |
| Galactic control / edge | Ready, image `v0.0.0-main-20261104-195508` |
| Native MASQUE authority / provider | Ready, image `v0.0.0-main-20261030-135500` |
| Provider service | `masque-provider.masque-system.svc:443`, TCP and UDP |
| Provider certificate | WebPKI name `masque-provider.masque-system.svc`, expiry `2027-01-27T21:32:21Z` |
| Grant workflow | `masque-authority ledger init`, then `grant create`; credential is printed once and is not stored by the authority |
| Project API | `datum-cloud` currently does not serve `connect.datumapis.com` CRDs |
| External reachability | No external MASQUE Service/Gateway was present; the provider is ClusterIP-only |

No staging resources or grants were created or changed. The implementation
could not safely perform the live CONNECT-IP, allowed/denied traffic, revocation,
cleanup, or UDP-blocked HTTP/2 checks because both prerequisites were absent:

1. the prototype Connect CRDs/controller and credential broker are not deployed
   in the project control plane; and
2. the native provider has no externally reachable authority whose certificate
   a user daemon can validate.

The existing historical Connect subnet lab resources were not reused as a
native MASQUE grant and were not modified. The current project had no
`connect-*` Network available during discovery, so no Network was guessed. A
future run should create uniquely labelled prototype resources in an explicitly
approved project, initialize a dedicated authority ledger/grant through the
documented workflow, expose the provider with a WebPKI DNS name, record the
authority-issued `/96` and advertised Network prefix, run one allowed service
probe and one denied port probe, revoke the grant or delete the binding, verify
session teardown, and remove only those labelled resources.

Cleanup state: **nothing created; nothing to clean up**.

## Production gaps

- authenticated broker deployment and automated Galactic grant lifecycle;
- trusted IAM group/subject resolution instead of protected Connector labels;
- policy enter/leave Events with durable set-diff state;
- placement assignment to externally reachable per-cell provider capacity;
- multi-location replacement, rollout compatibility, credential rotation, and
  revocation qualification;
- end-to-end staging data-plane and HTTP/2 fallback evidence.

