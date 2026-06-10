# Datum Connect Plugin

A `datumctl` plugin (`datumctl connect tunnel listen ...`) that wraps the Rust
[`datum-connect`](connect-lib/) binary to manage Datum Connect tunnels.

## Architecture

```
datumctl connect tunnel listen ...
  │
  ▼
┌─────────────────────────────────────┐
│ Go supervisor  (datumctl-connect)   │  reads stdout for JSON events
│   connect-plugin/tunnel/listen/     │  forwards stderr to terminal
│   connect-plugin/internal/*         │
│                                     │
│   ┌─────────────────────────────┐   │
│   │ Rust binary  (datum-connect)│   │  stderr → user (progress, ✓ lines)
│   │   connect-lib/bin/src/      │   │  stdout → Go supervisor (JSON)
│   │   connect-lib/lib/          │   │
│   └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

- **Go supervisor** (`connect-plugin/main.go`): datumctl plugin binary, parses
  tunnel-ready events from stdout, forwards signals (Ctrl+C), manages
  startup/grace timeout.
- **Rust binary** (`connect-lib/bin/`): headless tunnel agent driven by
  iroh + HTTPProxy APIs. Progress text goes to stderr; JSON lifecycle
  events go to stdout.
- **Rust library** (`connect-lib/lib/`): shared types, Kube API client,
  DatumCloud API bindings, heartbeat agent, tunnel service.

## Directory Layout

```
connect/
├── connect-plugin/          # Go plugin source
│   ├── main.go              # Plugin entrypoint
│   ├── tunnel/              # Cobra subcommands (listen, run, list, …)
│   │   └── listen/main.go   # Primary: spawns Rust binary, reads events
│   ├── internal/            # Go support packages
│   │   ├── binary/          # Rust binary discovery
│   │   ├── daemon/          # Background daemonisation
│   │   ├── env/             # Child environment builder (DATUM_SESSION, etc.)
│   │   ├── exec/            # Typed JSON message parser
│   │   ├── logfile/         # Log file management
│   │   ├── output/          # Formatted output (table/json/yaml)
│   │   ├── pidfile/         # PID tracking
│   │   ├── rbaccheck/       # Service-account RBAC validation
│   │   ├── signals/         # OS signal relay
│   │   ├── state/           # Daemon/run state persistence
│   │   ├── svcconfig/       # System service config builders
│   │   └── svcunit/         # systemd unit file generation
│   ├── e2e_test.go          # E2E tests (manifest, listen)
│   ├── e2e_interaction_test.go  # E2E tests (install, service, PID)
│   ├── go.mod / go.sum
│   ├── scripts/             # Build/release helpers
│   ├── testdata/            # Test fixtures
│   └── fake-datum-connect-test  # Test helper binary
├── connect-lib/             # Rust workspace
│   ├── Cargo.toml
│   ├── bin/                 # Binary crate (datum-connect)
│   │   └── src/
│   │       ├── main.rs      # Entrypoint, CLI, Listen handler
│   │       └── progress.rs  # Tunnel progress rendering (✓ / ○)
│   └── lib/                 # Library crate (connect-lib)
│       └── src/
│           ├── datum_cloud/  # API client, auth, env
│           ├── heartbeat.rs  # HeartbeatAgent
│           ├── tunnel.rs     # TunnelService
│           └── …
├── flake.nix                # Nix dev shell
├── Taskfile.yaml            # Build/test/install tasks
└── README.md
```

## Build

Requires Go toolchain and Rust/Cargo (provided via `nix develop`):

```bash
# Development build (debug)
nix develop ~/src/datum-cloud/datumctl  # Go toolchain
task build

# Release build with LTO + strip
task build:release

# Build and install to ~/.datumctl/plugins/
task install:release
```

Or use the helper scripts in `scripts/`.

## Testing

```bash
# Go unit tests
task test:go

# Rust unit tests
task test:rust

# Both
task test
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Two-binary architecture | Rust binary ships independently; Go supervisor handles dispatch, daemonisation, signal management. |
| `--json` mode always on | Go supervisor parses line-delimited JSON events from stdout; human text goes to stderr. |
| No `DATUM_ACCESS_TOKEN` in child env | Rust binary uses `DATUM_CREDENTIALS_HELPER` + `DATUM_SESSION` to exec helper for token. |
| Proxy verification retries indefinitely | Datum Cloud can take time to settle; user sees periodic `○ waiting for proxy …` messages every 10s. |
| State isolation | Plugin uses `~/.local/share/datumctl/connect/` — no OAuth files, no selected_context. |
