# Production Rust Improvements

Review target: `origin/develop` at `e256b6e4cb0fc24bb8cf510e710e7832b94453ba`.

`main` currently contains only the README, which points to `develop`. This review was converted into an implementation roadmap and is being remediated on top of the reviewed `develop` revision.

## Highest priority

- [x] **P0 — Make local state transactional and concurrency-safe.** `StateWrapper::update` publishes in-memory state before persistence succeeds, while repository writes are non-atomic and vulnerable to check-then-act races. Add validated `ProjectId`/`TunnelId` newtypes, serialized or versioned updates, atomic temp-file writes, exclusive key creation, restrictive permissions, and async filesystem operations. See [`state.rs:98`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/state.rs#L98) and [`repo.rs:101`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/repo.rs#L101).

- [ ] **P0 — Model Kubernetes reconciliation as partial success.** Creation mutates several resources sequentially, deletion returns early on errors, and local cleanup failures are only logged. Add typed per-resource outcomes, ownership labels, idempotent desired-state application, compensating cleanup, and repair/resume behavior. See [`tunnels.rs:738`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/tunnels.rs#L738) and [`tunnels.rs:1226`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/tunnels.rs#L1226).

- [ ] **P0 — Remove runtime panic paths and supervise spawned tasks.** Replace runtime `unwrap`/`expect` calls with structured errors, including CLI selection, filesystem setup, mutex access, progress-task joining, ticket serialization, and connector selection. Store and await task handles; expose task health and join failures. See [`main.rs:445`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/bin/src/main.rs#L445), [`main.rs:632`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/bin/src/main.rs#L632), and [`tunnels.rs:1391`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/tunnels.rs#L1391).

- [ ] **P0 — Stop guessing under ambiguity or uncertainty.** The code selects the first matching connector, backend, or connector class and silently falls back to default DNS/relay paths. Reject duplicates and malformed targets; use typed error categories instead of matching error strings. See [`tunnels.rs:1384`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/tunnels.rs#L1384) and [`tunnels.rs:1396`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/tunnels.rs#L1396).

- [ ] **P0 — Define a real authentication and token lifecycle.** `auth_update_watch` never receives updates, `auth_state` fabricates an external user, and authentication methods always succeed. Refreshed tokens can be accepted when expiry parsing fails, and plaintext tokens are distributed through watches. Remove unsupported plugin-mode APIs or model plugin authentication distinctly; redact secrets, validate refreshed tokens, and supervise refresh tasks. See [`datum_cloud/mod.rs:222`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/datum_cloud/mod.rs#L222) and [`external_token_source.rs:105`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/datum_cloud/external_token_source.rs#L105).

## Runtime and API hardening

- [ ] **P1 — Make cancellation, timeouts, and shutdown explicit.** Progress verification and DNS probing can loop indefinitely. Add cancellation tokens to long-lived tasks, request-level timeouts, bounded operation budgets, observable degraded states, and deliberate drain/cancel/flush behavior. Fix `refresh_projects` so failed probes remain eligible for retry. See [`progress.rs:169`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/progress.rs#L169) and [`heartbeat.rs:214`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/heartbeat.rs#L214).

- [ ] **P1 — Establish structured observability.** Centralize lifecycle JSON and human output behind an explicit sink while using structured `tracing` for diagnostics. Add OpenTelemetry spans and metrics for control-plane calls, storage writes, watches, retries, reconciliation phases, and verification latency. Replace interpolated errors and unobserved mutations with structured fields.

- [ ] **P1 — Separate wire types from domain types.** Add typed endpoint, hostname, resource-name, and protocol types. Keep Kubernetes serialization structs separate from validated domain models. Add `rename_all = "camelCase"` where appropriate and golden tests for emitted JSON/YAML patches. See [`http_proxy.rs:14`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/datum_apis/http_proxy.rs#L14).

- [ ] **P1 — Split the catch-all library and giant orchestration files.** `tunnels.rs` is about 2,257 lines and `main.rs` about 955 lines. Consider focused `connect-domain`, `connect-api`, `connect-storage`, and `connect-runtime` crates, with a thin CLI/output adapter and traits for control plane, credentials, probing, storage, clocks, and event sinks.

- [ ] **P1 — Make retries idempotent and list operations scalable.** Generated-name create retries can duplicate resources after an uncertain response. Use deterministic names or reconcile-after-uncertain-failure, typed retry classification with jitter, pagination, bounded concurrency, and indexed bulk reads. See [`tunnels.rs:573`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/tunnels.rs#L573) and [`tunnels.rs:1829`](https://github.com/datum-cloud/connect/blob/e256b6e4cb0fc24bb8cf510e710e7832b94453ba/connect-lib/lib/src/tunnels.rs#L1829).

## Testing and delivery

- [x] **P1 — Add Rust quality gates to CI.** The testing workflow now covers Rust changes on pushes and pull requests and runs:

  ```text
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace --locked
  ```

- [ ] **P1 — Add boundary and failure-path tests.** Cover concurrent state updates, failed persistence, path validation, duplicate connectors/classes, partial create/update/delete failures, token refresh failure, cancellation, retry idempotency, shutdown, task supervision, and exact wire payloads.

- [x] **P2 — Pin the toolchain and define performance evidence.** Add the missing `rust-toolchain.toml`, make Nix checks meaningful instead of `doCheck = false`, and add benchmarks/PGO workflow if performance claims are required. Publish comparisons only from the PGO binary.

- [x] **P2 — Clean up layout and dead code.** Move or remove the duplicate `datum_cloud_client.rs` stub; migrate prefixed files into meaningful directories where appropriate; correct the README's `tunnel.rs` versus `tunnels.rs` drift.

## Implementation status — 2026-09-03

Completed slices include atomic/private state and config persistence, cross-process state and key locking, validated repository path identifiers, exclusive and conflict-aware key creation, fail-closed connector/class selection, camel-case HTTP route payloads, bounded tunnel setup and verification, live control-plane client rotation, supervised credential refresh, reliable Go subprocess cleanup, pinned Rust/CI gates, and heartbeat re-probing on subsequent refresh events.

The remaining broad items require explicit durable contracts rather than safe mechanical cleanup:

- Kubernetes ownership/adoption, stable operation identity, per-resource outcomes, and repair semantics must be defined together before reconciliation or destructive cleanup changes.
- Plugin-mode authentication still needs an explicit API and token-validity contract (opaque tokens versus JWTs and required expiry behavior).
- `iroh_tickets::Ticket::to_bytes` is infallible at the trait boundary; removing its serialization panic requires a compatibility decision for the ticket encoding/API.
- Observability schemas, crate boundaries, and public compatibility guarantees need product-level scope before decomposition.

## Verification snapshot

- `cargo fmt --all -- --check`: passes.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passes.
- `cargo test --workspace --locked`: 110 tests pass outside the restricted sandbox (99 library, 11 binary).
- `go test ./...`: passes without a sibling `datumctl` checkout or committed test binaries.
- `go test -race ./internal/daemon ./internal/exec ./internal/signals ./internal/state`: passes.
- The restricted sandbox denies the `netmon` runtime test; the same test passes with the required host permissions.
- `nix flake check path:.` and `nix build path:. --no-link`: pass with the pinned Rust 1.98.0 toolchain; the package build runs its Rust checks.

## Suggested implementation order

1. Transactional storage and validated identifiers.
2. Typed reconciliation outcomes and idempotency.
3. Supervised task lifecycles, cancellation, and authentication state.
4. CI quality gates and failure-path regression tests.
5. Crate/file decomposition and observability expansion.
