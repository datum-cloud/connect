# Source review

Evidence for the [managed gateway endpoint enhancement](README.md), reviewed
2026-11-18. This is a source/configuration review, not live verification of DNS,
issuance, Karmada placement, certificate propagation or production listeners.
Statements about historical deployment inside infra documentation are that
document's evidence, not observations made during this review.

## Structural reference

### November 20 shared-transport revision

The updated design separates gateway endpoints from network bindings. The
implementation remains in draft Connect PR #74, based on required prototype
`73adbc35d08a3599bcd7075ec9e04e2144f8a750`, not main. Design PR #73 remains
documentation-only on main. The historical November 18 evidence below does not
describe the newer implementation.

Published Connect implementation `10b848a10b7d226429cd03e6878052b296688e73`
records the frozen contracts in `implementation.md` on its feature branch.
Its opt-in runtime component exports static managed mounts, without enabling
flags or permissions; Infrastructure selects it instead of a large inline patch.
Controller race tests with Kubernetes 1.37 envtest, native/Linux builds and both
Kustomize exports pass. Rust daemon tests report 41 passed/1 opt-in ignored;
successor tests report 39 passed/1 opt-in ignored. Run the physical-connection
fixtures with `cd connect-lib && cargo test -p datum-connect-daemon pool_tests --lib`
using Rust 1.98. Both protocols and separate security-context pools pass.

Published Galactic dependency `ed8dddbeca8ccb1b38623de0a5f4f344ef0b0e27`
(PR #1465) removes Network/VPC fields from endpoint registrations. Managed grant
creation instead requires Network UID, binding UID and a UID-pinned VPC reference.
`TestManagedEndpointMultiplexedAuthority` tests both protocols with one physical
dial, independent revocation and VPC recreation, using the real authority and a
fake packet backend. It is not operating-system datapath qualification.

Certificates dependency `4cec00395b3647737685addd697e40f2e94d3214` (PR #83)
preserves reservation-bound authorization and adds a binding-lifecycle regression.
Its reservation check uses project/gateway/metro/hostname and request name/UID,
not network identity. It proves certificate-service stability across binding
changes, not a complete Connect integration.

Connect's `galactic_masque::pool_tests` run its actual Rust client against TLS
loopback servers. They count physical connections, open separately credentialed
streams, deny selector/credential replay, revoke one stream, refresh credentials,
and reconnect after transport failure. They use a test packet responder, not a
live Galactic VPC. Controller tests separately pin per-binding identities and
preserve the endpoint through Network deletion/recreation. Exact final Connect
and Infra commits are recorded in the implementation PR and its contract log.

Live DNS/ACME issuance, Karmada delivery, operating-system packet paths, credential
frontend routing, external probes and qualified image/OCI digests remain release
gates. No deployment is established by these local source tests.

The structure and SVG style follow [Fleet’s machine-lifecycle enhancement](https://github.com/datum-cloud/fleet/blob/927035de2ea4ff9d1143ded85ece683cffd70200/docs/enhancements/machine-lifecycle/README.md).
Its diagrams use white backgrounds, pale blue and green control-plane boundaries,
rounded boxes, Arial text, and solid request / dashed response arrows. The two
editable SVGs in this enhancement use the same conventions.

The main proposal keeps the lifecycle, readiness, alternatives, and infrastructure
sections. Acceptance checks and source evidence live separately. Endpoint APIs
are still undecided, so this proposal does not include apply-ready manifests.

## Inspected revisions

Local checkout paths below are provenance, not requirements for readers. Commit
links identify source snapshots; local prototype commits were read on disk and
their availability on the remote was not independently established.

| Repository/checkouts | Revision | Interpretation |
| --- | --- | --- |
| `connect` | `5f7a378b512336f66125b00fc059f4c56fcc183f` | Original review checkout; older Workload architecture |
| `connect-wt-gateway-create-loop` | `73adbc35d08a3599bcd7075ec9e04e2144f8a750` | New logical gateway/placement and broker prototype |
| `connect-wt-managed-network-masque` | `61bb05dea9ecfe5af26f1d6e77cd9d1ccfcbedff` | Related native managed-network prototype documentation |
| `galactic` | `710d643bec2d7ad7388edc717575ce0dde800936` | Existing native service/adapter/authority source |
| `infra-connect-production` | `afdb79fff0f727bf4014bdca93af9fa7c6dab6d6` | Deployment configuration, not confirmation it is running |
| GitHub `milo-os/certificates` | `362000237f2cdbcab439be63d09401274db1918d` | Current GitHub HEAD resolved during review; README, API and validation source inspected |

All named Connect/Galactic/infra checkouts are under
`/Users/scotwells/repos/connect-analysis/`. Prototype, Galactic and infra snapshots
were clean at inspection. The proposal is published on `main`; implementation references remain pinned to
the reviewed development snapshots. It does not bring their code onto `main`.

## Capability and evidence matrix

| Evidence | Built/source behavior | Proposed or unverified gap |
| --- | --- | --- |
| [Connect prototype guide][connect-guide], [placement controller][connect-controller], [API types][connect-types] | Logical native contract; Location selector creates per-Location placements; assignment reference/status | Metro deduplication, managed reservation, cell/endpoint revision and lifecycle implementation |
| [Credential broker][connect-broker] | Sensitive POST boundary, `no-store`, provider Issuer interface, `masque.connect.datum.net/v1` descriptor | Production-ready endpoint/cell resolver, gateway-bound grant admission and issuance adapter |
| [Galactic service guide][masque-service], [service implementation][masque-service-code], [provider command][masque-command] | Native H3/H2, single authority, certificate reload hook/file-backed implementation | Dynamic multi-host registry, per-host SNI/scope selection, applied revision acknowledgment |
| [CONNECT-IP server][connectip-server], [H2 handler][connectip-h2] | Authority required at construction; H2 checks request host against single configured authority | Consistent registration-aware request admission on both transports |
| [MASQUE provider][masque-provider], [authority][masque-authority] | Edge/Lease/route admission; cell-scoped grants and retained `/96`; bounded refresh/revocation and retry rules | Endpoint-to-gateway scope binding and coordinated metro failover; no transparent cross-cell roaming |
| [Certificates README][cert-readme], [API][cert-api], [StoredSecretName][cert-secret], [validation][cert-validation] | DNS01, exact required delegation records, central stored key pair, UID consumer contract, protected-domain denial | Authorized internal managed-domain issuance and agreed rekey/revision signaling |
| [Certificate operator config][infra-cert-config], [issuers][infra-issuers], [Milo RBAC][infra-rbac] | Karmada cert-manager connection; Let's Encrypt DNS01 with externaldns-webhook and CNAME Follow; DNSRecordSet permissions | Connect service identity, zone ownership and reservation-bound authorization wiring |
| [Infra certificate guide][infra-cert-guide] | Documents central Karmada issuance and resulting Secret delivery to edge | New Connect selected-cell propagation and verified current deployment |
| [Cell MASQUE wiring][infra-masque], [cell certificates][infra-masque-certs] | Existing provider/authority component and internal service-name certificates | Public managed hostname, WebPKI delivery and shared-listener registration |

The requested `galactic/internal/connectip` path resolves in this snapshot to
`galactic/internal/edge/connectip`; source links use the actual path.

## Design decision after source review

On 2026-11-19, the design chose a Connect service-provider Project control plane
for internal lifecycle resources, managed DNS zone/record resources, and
certificate requests. DNS and Certificates reconcile those project resources.
This is an architectural decision, not an
implemented capability established by the pinned source snapshots. Dependent
systems retain their own issuance, distribution, and cell runtime resources.

## Important boundaries established by the sources

- The newer Connect guide explicitly distinguishes `managed-network-v1` from
  `legacy-v1`. Its placement type is per Location and its descriptor does not
  contain the proposed endpoint/certificate revision fields. Do not describe
  those additions as implemented or infer a metro from placement cardinality.
- Galactic's service has a `GetCertificate` hook, but the command supplies one
  certificate-file reloader and one `--authority`. A CNAME does not change that
  admission contract. Its readiness endpoint checks listeners and Lease, not
  public DNS convergence or per-host applied-certificate revision.
- Galactic attachment readiness can fail with `HostVRFMissing`; source states
  the provider joins an existing VPC host VRF. This proposal neither removes
  that prerequisite nor allocates a workload to satisfy it.
- Authority ledgers are VPC/cell-scoped; retired `/96` allocations are tombstones.
  A grant-create retry without the retained connector ID can allocate again.
  Existing revocation timing is documented in the authority guide and must be
  qualified with new integration paths, not assumed to cover hostname removal.
- The certificate service requires `issuance: DNS01` to avoid Auto's nonwildcard
  HTTP01 behavior. Random delegation targets in `requiredDNSRecords` are
  authoritative. Its immutable name set, UID-labelled stored Secret, and key
  custody remain the consumer contract, not project Secrets or status key bytes.
- `status.notAfter` signals renewal, but the README permits later-issued,
  shorter-lived emergency rekeys. The proposed delivery revision must not treat
  increasing expiry as the only permitted update.
- Protected platform-domain validation is independent of writer authorization.
  No inspected source establishes an already-working managed Connect domain
  exception. Direct restricted cert-manager issuance remains an alternative.

[connect-guide]: https://github.com/datum-cloud/connect/blob/73adbc35d08a3599bcd7075ec9e04e2144f8a750/docs/managed-network-galactic-prototype.md
[connect-controller]: https://github.com/datum-cloud/connect/blob/73adbc35d08a3599bcd7075ec9e04e2144f8a750/connect-controller/internal/controller/managed_network.go
[connect-types]: https://github.com/datum-cloud/connect/blob/73adbc35d08a3599bcd7075ec9e04e2144f8a750/connect-controller/api/v1alpha1/types.go
[connect-broker]: https://github.com/datum-cloud/connect/blob/73adbc35d08a3599bcd7075ec9e04e2144f8a750/connect-controller/internal/credentials/broker.go
[masque-service]: https://github.com/datum-cloud/galactic/blob/710d643bec2d7ad7388edc717575ce0dde800936/docs/edge/masque-service.md
[masque-service-code]: https://github.com/datum-cloud/galactic/blob/710d643bec2d7ad7388edc717575ce0dde800936/internal/edge/masque/service/service.go
[masque-command]: https://github.com/datum-cloud/galactic/blob/710d643bec2d7ad7388edc717575ce0dde800936/cmd/masque-provider/main.go
[connectip-server]: https://github.com/datum-cloud/galactic/blob/710d643bec2d7ad7388edc717575ce0dde800936/internal/edge/connectip/server.go
[connectip-h2]: https://github.com/datum-cloud/galactic/blob/710d643bec2d7ad7388edc717575ce0dde800936/internal/edge/connectip/h2.go
[masque-provider]: https://github.com/datum-cloud/galactic/blob/710d643bec2d7ad7388edc717575ce0dde800936/docs/edge/masque-provider.md
[masque-authority]: https://github.com/datum-cloud/galactic/blob/710d643bec2d7ad7388edc717575ce0dde800936/docs/edge/masque-authority.md
[cert-readme]: https://github.com/milo-os/certificates/blob/362000237f2cdbcab439be63d09401274db1918d/README.md
[cert-api]: https://github.com/milo-os/certificates/blob/362000237f2cdbcab439be63d09401274db1918d/api/v1alpha1/tlscertificate_types.go
[cert-secret]: https://github.com/milo-os/certificates/blob/362000237f2cdbcab439be63d09401274db1918d/api/v1alpha1/stored_secret.go
[cert-validation]: https://github.com/milo-os/certificates/blob/362000237f2cdbcab439be63d09401274db1918d/internal/validation/tlscertificate.go
[infra-cert-config]: https://github.com/datum-cloud/infra/blob/afdb79fff0f727bf4014bdca93af9fa7c6dab6d6/apps/certificates-system/base/config.yaml
[infra-issuers]: https://github.com/datum-cloud/infra/blob/afdb79fff0f727bf4014bdca93af9fa7c6dab6d6/apps/certificates-system/base/cluster-issuers.yaml
[infra-rbac]: https://github.com/datum-cloud/infra/blob/afdb79fff0f727bf4014bdca93af9fa7c6dab6d6/apps/certificates-system/base/milo-rbac/rbac.yaml
[infra-cert-guide]: https://github.com/datum-cloud/infra/blob/afdb79fff0f727bf4014bdca93af9fa7c6dab6d6/docs/platform/certificates/README.md
[infra-masque]: https://github.com/datum-cloud/infra/blob/afdb79fff0f727bf4014bdca93af9fa7c6dab6d6/apps/galactic-system/cell/components/masque/resources/galactic-masque.yaml
[infra-masque-certs]: https://github.com/datum-cloud/infra/blob/afdb79fff0f727bf4014bdca93af9fa7c6dab6d6/apps/galactic-system/cell/components/masque/resources/certificates/certificates.yaml
