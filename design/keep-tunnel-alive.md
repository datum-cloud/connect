# Keep Long-Lived Tunnels Alive Across User Re-Auth

Status: **In review — decisions locked (v1)**
Owner: connect team
Related: `feat/keep-tunnel-alive` branch
Date: 2026-09-01

### Locked decisions (v1)

| # | Decision | Value |
|---|----------|-------|
| Q1 | Auth/authorization ownership | **datumctl owns all authentication and authorization.** connect controls only the lifecycle of connectors/tunnels (and anything added to it). Provisioning, SA session storage, token minting, and RBAC all live in datumctl / the control plane. |
| Q2 | SA scope | **Per-tunnel SA** — a dedicated `datum_service_account` per tunnel. Bounds blast radius and gives fine-grained, independent revocation. |
| Q3 | RBAC placement | **Live via staff-portal** — the tunnel SA's connector-create `PolicyBinding` is applied on the live control plane, matching how user grants are managed today (not declarative in `infra`). |
| Q4 | Key rotation | **Rotation in v1.** SA key rotation is part of the first deliverable, not deferred. |

## 1. Problem statement

A long-lived Datum Connect tunnel must keep working even after the user who
started it has to re-authenticate (`datumctl auth login`). Today, a foreground
`datumctl connect tunnel listen ...` tunnel dies when the user's OAuth session
(access + refresh token) lapses, because nothing is renewing the tunnel's
control-plane lease with valid credentials.

The requirement is **seamless**: the user should not have to opt in or take any
extra action. Running `tunnel listen` should just produce a tunnel that survives
re-auth.

## 2. Background and verified findings

### 2.1 The authentication path

A tunnel authenticates to the Datum control plane and project control plane
(PCP) via a **credentials helper** invoked as a subprocess:

```
$DATUM_CREDENTIALS_HELPER auth get-token --session $DATUM_SESSION
```

- The `DATUM_*` env for every plugin (including connect) is set by datumctl in
  `internal/plugindispatch/dispatch.go::BuildEnv` — notably
  `DATUM_SESSION=<activeSession>`.
- connect passes those through to the Rust binary via
  `connect-plugin/internal/env/build.go::Build`, and the Rust binary drives the
  token source in `connect-lib/lib/src/datum_cloud/external_token_source.rs`.

### 2.2 The helper already has a refreshable-token flow

`datumctl auth get-token` uses an OAuth2 token source
(`datumctl/internal/authutil/credentials.go::persistingTokenSource`). When the
access token is expired it transparently uses the stored **refresh token** to
mint a new access token.

The connect Rust side already re-executes the helper proactively (60 s before
JWT expiry) and on 401 (`external_token_source.rs::run_refresh_loop`,
`heartbeat.rs::force_refresh_auth`), and rebuilds the kube client on token
change (`project_control_plane.rs`).

**Conclusion:** the tunnel already survives ordinary access-token expiry. It
only breaks when the **refresh token** itself is expired/revoked, at which point
`credentials.go` (lines ~145-150) returns:

> "Authentication session has expired or refresh token is no longer valid.
> Please re-authenticate using: `datumctl auth login`"

The helper then fails; `external_token_source` backs off with the dead token;
the heartbeat can no longer renew the PCP **Lease** (default 30 s) and the
tunnel is torn down server-side.

### 2.3 A durable, self-refreshing identity already exists

datumctl supports **`datum_service_account` sessions** (`datum_service_account`
credential = JSON key with a private RSA key). Its token source
(`datumctl/internal/authutil/serviceaccount.go::serviceAccountTokenSource`)
**mints and exchanges a fresh JWT on demand forever** — no refresh token, no
human re-login — as long as the private key is stored (keyring) and valid.

**This is the mechanism that satisfies the requirement.** Tunnels
authenticated as a `datum_service_account` never depend on the user's
interactive session.

### 2.4 The gap is the foreground `listen` path

| Path | Identity | Survives user re-auth? |
|------|----------|------------------------|
| `tunnel install` + `tunnel run` (systemd service) | Requires `--session` (a service-account session); persisted in `TunnelConfig.Session` | ✅ yes |
| `tunnel listen` (foreground) | Inherits `DATUM_SESSION=<active user session>`; no `--session` flag | ❌ no |

The foreground `listen` path — exactly what `datumctl connect tunnel listen
--endpoint ...` does — runs as the **user's interactive session** and breaks on
re-auth.

### 2.5 RBAC boundary

The identity creating a `Connector` must have permission to
`create connectors.networking.datumapis.com` (plus associated resources) on the
target project control plane, in namespace `default`. This is granted via a
Milo `PolicyBinding` binding the identity to a role such as
`networking.datumapis.com-connector-admin` (defined in
`network-services-operator/config/iam/roles/connector-admin.yaml`). Working
users are bound scoped to a project on the live control plane.

## 3. Design goal

Make the tunnel's identity a **durable service-account identity by default**,
with **no user opt-in**, so `tunnel listen` produces a tunnel that survives
re-auth.

## 4. Options considered

### Option A — Seamless automatic service-account identity (recommended direction)

When a tunnel is created, the connect plugin (in coordination with datumctl)
**transparently resolves (and if absent, provisions) a `datum_service_account`
session** for the tunnel, and runs the tunnel under that session instead of the
user's interactive session.

Sub-variants for SA scope:

- **A1 — Per-user SA.** One `datum_service_account` per user, shared by all
  their tunnels. Matches the existing `install`/service SA contract; simplest;
  coarsest-grained revocation.
- **A2 — Per-tunnel SA.** A dedicated SA per tunnel. Finer-grained RBAC and
  independent revocation, but more key material and provisioning.
- **A3 — Reuse/encode the existing service contract.** Make the foreground
  path behave like the already-SA-backed `install` path, auto-creating the SA
  session on first use.

### Option B — Expose an explicit opt-in (rejected)

Add a `--session` / `--service-account` flag and require the user to choose.
Rejected: violates the "no opt-in" requirement.

### Option C — Only document the service path (rejected)

Point users at `install` + `run`. Rejected: does not make `listen` seamless.

## 5. Recommended approach

Proceed with **Option A1 → A2 semantics: per-tunnel service-account identity,
transparent**. Each tunnel is authenticated as its own `datum_service_account`
session, automatically and with no user opt-in.

Ownership is split along the established boundary:

- **datumctl owns all authentication and authorization.** It provisions the
  per-tunnel SA, stores its key (keyring), mints tokens
  (`serviceAccountTokenSource`), and owns the RBAC grant for the SA on the PCP.
  connect sees only a credentials helper invocation
  (`$DATUM_CREDENTIALS_HELPER auth get-token --session <tunnel-sa-session>`).
- **connect controls connector/tunnel lifecycle.** It decides when a tunnel
  exists, requests its SA session from datumctl, and runs `listen` under it.

Concretely:

1. **Tunnel identity resolution (connect ↔ datumctl):**
   - On first `tunnel listen` for a given tunnel, connect asks datumctl for the
     tunnel's SA session (via the helpers datumctl exposes); datumctl
     provisions a dedicated `datum_service_account` for that tunnel and records
     a session.
   - `listen` runs the child with `DATUM_SESSION=<tunnel-sa-session>`, replacing
     the inherited user session by default.
   - No new mandatory flags; unaffected for tunnels that already carry an
     explicit session.

2. **Provisioning and storage (datumctl):**
   - Provision the per-tunnel `datum_service_account` via a datumctl-owned,
     non-interactive path (reusing `RunServiceAccountLogin` /
     `UpsertSession`), keyed by tunnel.
   - Store the SA private key in the datumctl keyring (existing
     `datum_service_account` session storage).

3. **RBAC (control plane, via staff-portal):**
   - Bind the tunnel SA to a PCP role granting
     `create connectors.networking.datumapis.com` (e.g.
     `networking.datumapis.com-connector-admin`) for the relevant project.
   - Applied **live via staff-portal**, matching how user grants are managed
     today.

4. **Revocation / rotation (datumctl + portal):**
   - Rotation is required in v1: datumctl provides the mechanism and the portal
     can mint a fresh SA credential; on key loss/rotation the tunnel SA fails
     closed (tunnel pauses rather than silently continuing on a stale key).

5. **UX:** seamless; the automatic identity is invisible unless diagnostics
   are on.

## 6. Security considerations

- A stored long-lived SA private key is high value. With **per-tunnel SAs**, a
  single key breach is bounded to that one tunnel; RBAC limits what the SA can
  do on the PCP.
- **Key rotation is required in v1** (Q4). Rotation, revocation, and
  regeneration must be supported from day one.
- The SA must inherit only the minimum needed permissions on the PCP
  (connector create/patch, lease renew) — not a general admin.
- On auth failure (key rotated/revoked/lost), the tunnel must **fail closed**:
  pause the lease renewal and surface a clear diagnostic, never silently
  continue with a stale/unauthorized identity.

## 7. Out of scope (for this pass)

- Migrating already-installed user-session tunnels to per-tunnel SAs (can be a
  follow-up migration).
- Declarative `infra` provisioning of SA RBAC (Q3 chose live via staff-portal).
- Per-user shared SA / pooling of tunnel identities.

## 8. Implementation plan (proposed phases)

1. **Phase 1 — datumctl per-tunnel SA provisioning + rotation:**
   - datumctl provisions a dedicated `datum_service_account` session per tunnel
     (non-interactive, keyed by tunnel); stores the key in the keyring.
   - datumctl `auth get-token --session <tunnel-sa-session>` returns the
     self-minting SA token; rotation/regeneration path included.
   - Add tests (SA token source, provisioning, rotation).
2. **Phase 2 — connect identity selection:**
   - `tunnel listen` resolves the tunnel's SA session from datumctl by default
     and runs the child with `DATUM_SESSION=<tunnel-sa-session>`; diagnostics
     for when it falls back to the user session.
   - Add tests (fake helper standing in for the SA-backed helper).
3. **Phase 3 — RBAC via staff-portal:**
   - Grant the per-tunnel SA connector-create on the target PCP via the live
     control plane; verify with an end-to-end `tunnel listen` that outlives a
     simulated user re-auth.
4. **Phase 4 — hardening / doc:**
   - Fail-closed behavior on auth loss; README "Key Design Decisions" update.

## 9. Remaining items to resolve during implementation

1. datumctl API surface for per-tunnel SA provisioning/selection that connect
   consumes (exact env/helper contract).
2. How a per-tunnel SA is keyed (tunnel name vs resource ID) and scoped to the
   right project/PCP.
3. Rotation mechanics: regeneration flow, when a key is considered stale, and
   the fail-closed diagnostic touchpoint.
4. staff-portal flow for binding a per-tunnel SA to connector-create on the
   relevant PCP.
