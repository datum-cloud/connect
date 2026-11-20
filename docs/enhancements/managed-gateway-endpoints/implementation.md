# Managed endpoints implementation

This branch depends on gateway prototype commit
`73adbc35d08a3599bcd7075ec9e04e2144f8a750`, not the scaffolding on main.
Design: Connect PR #73. No live deployment is authorized.

## Revised shared transport contract (2026-11-20)

Agreed with Galactic, Certificates and Infrastructure: gateways and endpoints
are independent of networks. Customer bindings explicitly name gateway,
connector and network. Policies must explicitly list allowed `networkRefs`;
an old policy without this list grants no managed network access. Gateway
permission alone never authorizes a stream.

`MASQUEEndpoint` drops `networkUID` and `vpcRef`. Its scope contains only
`endpointUID`, `customerProjectUID`, `gatewayUID`, `cell`, `hostname`.
Galactic managed CreateRequest requires separate `NetworkUID`, `BindingUID`
and UID-pinned `VPCRef`. ConnectGrant durably pins `networkName`, `networkUID`,
`vpcRef` and binding identity. Network recreation revokes only those grants.
Certificates' reservation authorization, certificate revision, and applied
instance status contracts are unchanged.

Operator JSON separates `capacity:[{metro,assignment:{cell,provider,frontend}}]`
from `reachability:[{networkUID,cell,vpcRef:{namespace,name,uid}}]`.
`cells` and `probeURL` retain their existing shape. A binding requires an exact
reachability mapping in the already selected cell; no roaming is allowed.
Endpoint probe fields are `endpointUID`, `revision`, `certificateRevision`,
`cell`, `checkedAt`, `h3`, `h2`, `dns`; the old `vpc` boolean is removed.
Network forwarding qualification is separate, per binding.

Public hostname labels are allocated randomly once and stored in the reservation.
UIDs remain internal recreation fences, never user inputs or public host labels.
The client shares one physical transport per endpoint and security context,
with separately authenticated streams, refresh and cancellation per binding.
Local overlapping routes remain unsupported. Server fake-backend tests, actual
Rust client pooling tests, and deployed packet qualification are separate gates.

The controller and Rust client implement this contract. Certificates dependency is
`4cec00395b3647737685addd697e40f2e94d3214` (unchanged runtime contract).

## Lifecycle contracts

Connect owns namespaced `connect.datumapis.com/v1alpha1 ConnectEndpoint`
(`connectendpoints`) in an explicitly configured service-provider Project.
It has no customer owner reference. Immutable identity is
`spec.customerProjectUID`, `gatewayUID`, `metro`, `hostname`. `spec.lifecycle`
is `Active`, `Deleting`, or `Retired`. Assignment pins one existing cell, independent of VPCs.
Customer placements share the endpoint when Locations resolve to the same metro.
Gateway availability counts distinct metros, not duplicate Location placements.

Certificates agreed: `TLSCertificate.spec.managedAuthorization` contains
`reservationName` and `reservationUID`. Requests use DNS01 and exactly one name.
Authorization reads the pinned service Project, checks the trusted writer and
cluster, reservation UID, identity, hostname, namespace, `spec.lifecycle=Active`,
`status.phase=Active`, and `status.certificateRef.name/uid`. Create the reservation,
publish the certificate name, create the request, then bind its returned UID.
`TLSCertificate.status.certificateRevision` is lowercase SHA256 of leaf DER.
Publish the exact `status.requiredDNSRecords` CNAME. Keys never enter Projects.

Galactic agreed: namespaced `galactic.datumapis.com/v1alpha1 MASQUEEndpoint`
spec contains `endpointUID`, `customerProjectUID`, `gatewayUID`,
`metro`, `cell`, `provider`, `hostname`,
positive monotonic `revision`, `certificateRef:{name,revision}`, and `enabled`.
Identity is immutable. Revision increases for certificate changes and disable.
Certificate revision is leaf DER SHA256, never ordered by expiry.
`status.instances[]` keys on `instanceName`, with `instanceUID`, `podUID`,
`observedRevision`, `appliedRevision`, `appliedCertificateRevision`,
`state` (Applied/Disabled/Error), `forwardingStopped`, `lastHeartbeatTime`,
and `message`. Provider durable fences retain endpoint UID and revision.

Relevant instances come from provider-matching EdgeInstances and their
same-name, owner-UID-bound Leases, never the acknowledgment list. Check Lease
renewal/duration/released state and acknowledgments no older than ten seconds.
Readiness requires all relevant instances, exact revisions, and fresh external
DNS/TLS/H3/H2 probes. A Karmada delivery acknowledgment alone is insufficient.

Infrastructure agreed: per-endpoint Karmada PropagationPolicy exact resource
selectors for registration and Secret, `propagateDeps:false`, one clusterNames
entry, no failover. Direct read-only cell clients inspect membership and applied
status. Shared zone and capacity are operator-owned and never endpoint-owned.

## Durable lifecycle

`ConnectEndpoint` also records customer Project/name and gateway namespace/name.
Assignment contains only `cell`, `provider` and `frontend`. Identity and an established assignment are
immutable. Reservation creation is deterministic and retry-safe. No endpoint
owns a Project, shared zone, VPC or provider deployment.

`status.revision` fences registration changes. `status.certificateRevision`
tracks the desired leaf, `status.deliveredSecrets` records every versioned
Secret name before delivery, and `status.verifiedAt` expires readiness after ten
seconds. Secret names are `<endpoint-name>-<leaf-DER-sha256>`. Each carries
`masque.galactic.datumapis.com/endpoint-uid` and
`masque.galactic.datumapis.com/certificate-revision` annotations. Karmada policy
selects the registration and all retained versions in exactly one cell. Previous
versions are removed only after the replacement is applied and externally
verified; actual cell absence is required before forgetting their names.

The consumer requires current-generation TLSCertificate Ready, pinned request
UID and source Secret UID label, matching key/certificate, exact hostname,
validity and leaf revision. Shorter-lived rekeys are accepted. Five minutes
before expiry, DNS is withdrawn even if issuance is failing.

Readiness reads the selected cell directly, including exact registration scope,
certificate name/revision and enable state. It does not rely on reflected
Karmada ResourceBinding status. Stale or unavailable membership blocks readiness
and cleanup conservatively. Galactic's runtime lease gate remains authoritative;
`forwardingStopped` is not a claim of verified kernel route withdrawal.

Cleanup is persisted in `status.cleanupStep`: disable at a new revision, await
all fresh Disabled/forwardingStopped acknowledgments, withdraw DNS, drain cached
DNS for two minutes, remove registration and all keys, delete the certificate
request, await central stored-key removal, remove challenge, retire grants, retain
the reservation. A customer Project deletion cannot garbage-collect this state.
API failures are not interpreted as deletion or allowed to stop independent
certificate renewal and expiry handling. Endpoint DELETE is not granted to
the runtime identity; service Project retention is an infrastructure prerequisite.

Re-adding a metro for the same live Project/gateway UIDs may reactivate
only after complete retirement. Hostname, endpoint UID and cell stay unchanged.
`status.activationRevision` starts a new credential epoch above the disable
revision. Old grant receipts and allocation tombstones remain retired. Draining
reservations cannot reactivate. Recreated gateways get different reservations.

`ConnectGrant` (`connect.datumapis.com/v1alpha1`, plural `connectgrants`) stores
immutable endpointName/UID, bindingName/UID, networkName/UID, vpcRef,
policyRevision, connectorID and cell,
plus `status.retiring/retired`. It never stores a credential. The broker uses
Galactic's public `pkg/masquegrant` facade, not a new authority HTTP API. Retries
rotate the same deterministic connector, preserving its /96; revocation retains
the allocation tombstone. No broker call initializes a missing ledger.

## Runtime configuration

The existing Connect controller/ServiceAccount owns reconciliation. Required
flags when enabled:

Opt-in component `connect-controller/config/components/managed-endpoints/runtime`
provides only static read-only mounts/volumes, including the projected Karmada
token. From `config/base/manager`, select
`../../components/managed-endpoints/runtime`. It does not enable the feature,
create credentials, change RBAC or add flags; Infra supplies those separately.

```text
--managed-endpoints
--endpoint-project-kubeconfig=/etc/connect/endpoint-project/kubeconfig.yaml
--endpoint-namespace=<service-project-namespace>
--endpoint-domain=<shared-zone-domain>
--endpoint-zone=<existing-DNSZone-name>
--karmada-kubeconfig=<delivery-kubeconfig>
--certificate-kubeconfig=/etc/connect/certificates/kubeconfig.yaml
--certificate-namespace=<central-certificate-secret-namespace>
--endpoint-runtime-namespace=masque-system
--endpoint-config=<operator-config.json>
```

`--endpoint-provisioning=false` stops new reservation creation/reactivation,
not renewal or cleanup. Configuration shape (all values operator supplied):

```json
{
  "capacity": [{
    "metro": "metro-id",
    "assignment": {
      "cell": "existing-cell", "provider": "existing-provider",
      "frontend": "existing-cell-frontend.example.test"
    }
  }],
  "reachability": [{
    "networkUID": "customer-network-uid", "cell": "existing-cell",
    "vpcRef": {"namespace": "vpc-namespace", "name": "vpc", "uid": "vpc-uid"}
  }],
  "cells": {"existing-cell": {
    "kubeconfig": "/etc/connect/cells/reader.yaml",
    "grantKubeconfig": "/etc/connect/cells/grants.yaml"
  }},
  "probeURL": "https://trusted-probe.example.test/endpoints"
}
```

The probe GET path appends the endpoint UID. Its JSON report must contain exact
`endpointUID`, `revision`, `certificateRevision`, `cell`, a `checkedAt` timestamp
no older than ten seconds, and `h3`, `h2`, `dns` all true. HTTPS trust comes
from the controller's configured trust store. No probe service is bundled, no
synthetic success is permitted, and omission fails closed.

The optional broker requires `--credential-listen-address`,
`--credential-tls-cert` and `--credential-tls-key`. Its POST route is:

```text
/apis/resourcemanager.miloapis.com/v1alpha1/projects/{project}/control-plane/apis/connect.datumapis.com/v1alpha1/namespaces/{namespace}/connectnetworkbindings/{binding}/connection-credentials
```

It uses only the caller's bearer token for a named binding `create`
`connectnetworkbindings/connection-credentials` SelfSubjectAccessReview and GET.
Fresh privileged reads then enforce Connector readiness, policy, Project,
gateway, Network and endpoint UIDs. A final read rejects revocation during mint.
Responses are no-store, errors never return credentials. Frontend routing to this
listener is a separate release gate and remains disabled by default.

The pinned service-project identity is
`system:managed-endpoints@connect.datumapis.com`, not system:masters. Certificates
uses its separate pinned reservation reader and exact writer/Project admission
checks. Cell observer clients read registration, EdgeInstance and Lease objects;
Secret GET is also needed to verify cleanup. Central source Secret GET currently
has namespace scope. Both key-read residual privileges are explicit; they must
not be granted to customer identities. Grant clients are separate and may update
only operator-provisioned named ledgers, never endpoint fences.

## Validation and release gates

Local tests cover real Galactic facade mint/rotate/retire and retained /96,
missing ledger/fence denial, source key/UID/revision checks, exact DNS challenge,
single-cell policy, shorter rekey, expiry withdrawal, partial membership and
stale acknowledgments, durable deletion, retry-safe metro collapse, reactivation
epochs and real Kubernetes CRD immutability validation. Fake clients do not
establish DNS propagation, ACME issuance, Karmada behavior or packet forwarding.

Passed locally: the full controller race suite (including Kubernetes 1.37
envtest), native macOS build, Linux/amd64 cross-build, and stock Kustomize renders
of both service-only and default customer exports. The resource fixture drives
central certificate consumption through generated delivery, instance/Lease
acknowledgments, DNS and readiness, with an explicitly simulated probe. The
separate broker fixture calls the published Galactic grant/ledger implementation.

Commands used:

```sh
make manifests CONTROLLER_GEN='go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.21.0'
KUBEBUILDER_ASSETS=<Kubernetes-1.37-envtest> go test -race ./...
go build -o /tmp/connect-managed-controller ./cmd/controller
GOOS=linux GOARCH=amd64 go build -o /tmp/connect-managed-controller-linux ./cmd/controller
kubectl kustomize config/components/managed-endpoints/crd
```

Dependencies:

- Certificates: `4cec00395b3647737685addd697e40f2e94d3214`, draft PR milo-os/certificates#83.
- Infrastructure: `c77e72527ed35ecb3d55cca8b5d49427427258c4` (implementation base
  `4edfe175ce00fd0c044bd6072a834ae1461b35ec`), draft PR datum-cloud/infra#9647.
- Galactic: `df3279afb62d05c82e964fcc7345cfeacf6fd3a8`, draft PR datum-cloud/galactic#1465;
  Go module `v0.9.5-0.20261120152434-df3279afb62d`, without local replacements.
  This CI correction changes API comments and the load-safe CRD export, not
  endpoint, grant or runtime contracts.

The Galactic dependency requires Go 1.26.4 and Kubernetes Go modules 0.37.2;
the controller module follows those minimum versions. Controller generation
remains pinned to 0.21.0 for consistent existing manifests.

Release remains blocked on qualified image/OCI digests, real trusted probe
service, authenticated credential frontend routing and live ACME/DNS/Karmada/
Galactic H3/H2/VPC qualification. Infrastructure wrappers are opt-in/suspended.
Nothing in this branch merges, deploys or claims those live results.

## Shared-transport validation and migration

Run `cd connect-lib && cargo test -p datum-connect-daemon pool_tests --lib` with
Rust 1.98. The actual Rust client tests use real loopback TLS/TCP and QUIC peers,
count physical connections and compare distinct stream IDs. They cover two VPC
streams, denied third/replayed selectors, one-stream revocation, credential expiry,
refresh and reconnect after a physical connection failure. No OS adapter is
created. Separate project/security-context pools open separate connections.
The privileged helper continues to reject overlapping active routes.
The daemon owns a pool per enrolled project/security context; each request has
its own bearer. A single H3 datagram reader dispatches by stream ID. Cancel/reset
never closes a sibling's connection. Credential refresh terminates only the
expiring stream; the durable network reconciler remints each attachment separately.

Controller tests cover shared endpoints, named network policy, missing reachability,
Network deletion/recreation, durable UID pins and unchanged sibling availability.
Real envtest validates the regenerated schemas. Galactic's separate
`TestManagedEndpointMultiplexedAuthority` uses its real authority and a fake packet
backend. Neither suite qualifies live DNS/ACME/Karmada or operating-system routing.

`legacy-v1` retains required gateway networkRef and its old transport. Managed
bindings require explicit networkRef; unscoped policies deny access until an
administrator adds networkRefs. Never infer a wildcard during migration. Drain
experimental old managed endpoints before upgrading their internal schemas;
there is no live migration claim. Old operator JSON with endpoint Network/VPC
fields is rejected rather than silently reinterpreted. Recreate bindings to approve
replacement Network/VPC identities; old durable receipts continue fencing reuse.

Final local Rust validation: daemon library 41 passed/1 ignored; successor client
39 passed/1 ignored (serial); both H3/H2 pooling tests and the helper's live-route
overlap rejection test passed. The ignored tests are existing opt-in cases, not
same-connection coverage. No live credentials, interfaces or deployments were used.
