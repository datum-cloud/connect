//! Plugin-mode tunnel agent (`datum-connect`). The Go-side `datumctl connect`
//! plugin spawns this binary as a subprocess and communicates over stdout
//! (line-delimited JSON when `--json`, human text otherwise).
//!
//! # JSON EVENT CONTRACT (emitted by this binary's main handler)
//!
//! See `progress.rs` for setup-phase events (`tunnel_progress`,
//! `tunnel_verifying`, `tunnel_verified`).
//!
//! | Event type                | When                                       | Fields                                                                            |
//! |---------------------------|--------------------------------------------|-----------------------------------------------------------------------------------|
//! | `tunnel_created`          | new HTTPProxy created                      | `id`                                                                              |
//! | `tunnel_updated`          | label/endpoint changed                     | `id`, `label`, `endpoint`, `hostnames`                                            |
//! | `tunnel_ready`            | setup complete AND proxy reachable (non-5xx) | `id`, `label`, `endpoint`, `hostnames`, `endpoint_id`, `status`, `elapsed_secs` |
//! | `tunnel_login_lost`       | LoginState::Missing observed mid-run       | `id`, `message`                                                                   |
//! | `tunnel_terminal_failure` | progress.terminal_failure() Some mid-run   | `id`, `message`                                                                   |
//! | `tunnel_deleted_upstream` | get_active_progress -> None mid-run        | `id`, `message`                                                                   |
//! | `tunnel_disabled`         | cleanup before exit                        | `id`                                                                              |
//! | `tunnel_deleted`          | `delete` subcommand only                   | `id`, `deleted: true`                                                             |
//!
//! `tunnel_ready` is the single event that drives the Go supervisor's
//! `gotReady` handshake (`connect/tunnel/listen/main.go:160-176`, established
//! in commit `1bb9552`). It MUST NOT be removed, renamed, or have its emission
//! site moved without coordinating the Go side.

use std::io::Write;
use std::sync::OnceLock;

use clap::{Parser, Subcommand};
use n0_error::StdResultExt;
use tracing_subscriber::{
    filter::EnvFilter,
    layer::SubscriberExt,
    reload::{self, Handle},
    util::SubscriberInitExt,
    Registry,
};

use connect_lib::datum_cloud::env::ApiEnv;
use connect_lib::datum_cloud::external_token_source::ExternalTokenSource;
use connect_lib::datum_cloud::DatumCloudClient;
use connect_lib::{HeartbeatAgent, ListenNode, Repo, SelectedContext, TunnelService};

mod progress;

type ReloadHandle = Handle<EnvFilter, Registry>;
static RELOAD_HANDLE: OnceLock<ReloadHandle> = OnceLock::new();

fn init_tracing() {
    let default_directive = "datum_connect=info";
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_directive));
    let (filter_layer, handle) = reload::Layer::new(filter);
    // Best-effort: if a subscriber is already installed (e.g. duplicate call in tests),
    // skip without panicking.
    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init();
    let _ = RELOAD_HANDLE.set(handle);
}

fn silence_tracing() {
    if let Some(handle) = RELOAD_HANDLE.get() {
        let _ = handle.modify(|f| *f = EnvFilter::new("off"));
    }
}

fn restore_tracing(prev: &str) {
    if let Some(handle) = RELOAD_HANDLE.get() {
        let _ = handle.modify(|f| *f = EnvFilter::new(prev));
    }
}

fn current_filter_string() -> String {
    std::env::var("RUST_LOG").unwrap_or_else(|_| "datum_connect=info".to_string())
}

#[derive(Parser, Debug)]
#[command(name = "datum-connect", about = "Datum Connect tunnel agent (plugin mode)")]
struct Args {
    #[clap(long, env = "DATUM_CONNECT_DIR")]
    repo: Option<std::path::PathBuf>,
    #[clap(long, env = "DATUM_PROJECT")]
    project: Option<String>,
    #[clap(long, global = true)]
    json: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all tunnels in the current project.
    List,
    /// Start a tunnel exposing a local service.
    Listen {
        #[clap(long)]
        label: Option<String>,
        #[clap(long)]
        endpoint: Option<String>,
        #[clap(long)]
        id: Option<String>,
    },
    /// Update an existing tunnel.
    Update {
        #[clap(long)]
        id: String,
        #[clap(long)]
        label: Option<String>,
        #[clap(long)]
        endpoint: Option<String>,
    },
    /// Delete a tunnel.
    Delete {
        #[clap(long)]
        id: String,
    },
}

/// Why the Listen handler's runtime select-loop terminated. Drives the
/// final exit status: CtrlC = clean exit 0; TerminalFailure / DeletedUpstream
/// = exit 1 with an n0_error::anyerr! message.
enum ExitReason {
    CtrlC,
    TerminalFailure,
    DeletedUpstream,
}

fn resolve_project(project_id: &str) -> SelectedContext {
    SelectedContext {
        project_id: project_id.to_string(),
        project_name: project_id.to_string(),
        org_id: String::new(),
        org_name: String::new(),
        org_type: String::new(),
    }
}

#[tokio::main]
async fn main() {
    let result = run().await;
    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

async fn run() -> n0_error::Result<()> {
    let _ = rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| n0_error::anyerr!("failed to install ring crypto provider for rustls"))?;

    init_tracing();

    let session: Option<String> = std::env::var("DATUM_SESSION").ok();
    if session.is_none() && std::env::var("DATUM_PLUGIN_MODE").map(|v| v != "1").unwrap_or(true) {
        return Err(n0_error::anyerr!(
            "neither DATUM_SESSION nor DATUM_PLUGIN_MODE=1 set — this binary runs in plugin mode only"
        ));
    }

    let token_source = ExternalTokenSource::from_env(session.clone())
        .map_err(|e| n0_error::anyerr!("failed to create token source: {e}"))?;

    if let Some(ref s) = session {
        if let Ok(helper) = std::env::var("DATUM_CREDENTIALS_HELPER") {
            token_source.start_refresh(helper, s.clone());
        }
    }

    let datum = DatumCloudClient::with_external_token_source(ApiEnv::default(), token_source);

    let args = Args::parse();

    let json = args.json;

    let project_id = match args.project {
        Some(ref pid) => pid.clone(),
        None => {
            let session = std::env::var("DATUM_SESSION")
                .ok()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    n0_error::anyerr!(
                        "no project set — pass --project or run 'datumctl config set project <name>'"
                    )
                })?;
            session
        }
    };

    let ctx = resolve_project(&project_id);
    datum.set_selected_context(Some(ctx)).await?;

    let repo_path = match args.repo {
        Some(p) => p,
        None => match Repo::default_location() {
            Ok(p) => p,
            Err(e) => {
                eprint!("{e}");
                std::process::exit(64);
            }
        },
    };
    let repo = Repo::open_or_create(repo_path).await?;

    match args.command {
        Commands::List => {
            let node = ListenNode::new(repo.clone()).await?;
            let service = TunnelService::new(datum.clone(), node.clone());
            let tunnels = service.list_active().await?;
            let output: Vec<serde_json::Value> = tunnels
                .iter()
                .map(|t| {
                    let status = if t.accepted && t.programmed {
                        "ready"
                    } else if t.accepted {
                        "accepted"
                    } else {
                        "pending"
                    };
                    serde_json::json!({
                        "type": "tunnel",
                        "id": t.id,
                        "label": t.label,
                        "endpoint": t.endpoint,
                        "status": status,
                        "enabled": t.enabled,
                        "hostnames": t.hostnames
                    })
                })
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&output).anyerr()?);
            } else {
                if output.is_empty() {
                    println!("No tunnels found.");
                }
                for t in &output {
                    println!("{}", serde_json::to_string(t).anyerr()?);
                }
            }
        }
        Commands::Listen { label, endpoint, id } => {
            // Plan 12-02 resolution rules (replaces plan 12-01 stubs):
            //   --endpoint only        → existing behaviour (no node/service yet)
            //   --id only              → real resolution via TunnelService::get_active;
            //                            inherit endpoint from the existing tunnel
            //   --id + --endpoint      → validate that the named tunnel already
            //                            references that endpoint; error otherwise
            //   neither flag           → picker with auto-adopt on len==1, error on len==0
            //
            // Informed by datum-cloud/app@ca4470f (tunnel listen --id pins existing
            // tunnel and preserves its hostname) and @a68d8ae (--id alone resumes
            // an existing tunnel; --id+--endpoint must agree).
            //
            // The id branches pre-build (node, service) so we can call
            // get_active(&id). They stash the result in `preresolved_ns` so the
            // downstream block reuses them instead of re-creating.
            let mut preresolved_ns: Option<(ListenNode, TunnelService, connect_lib::TunnelSummary)> =
                None;
            let endpoint: String = match (endpoint, id) {
                (Some(ep), None) => ep,
                (None, Some(id)) => {
                    let node = ListenNode::new(repo.clone()).await?;
                    let service = TunnelService::new(datum.clone(), node.clone());
                    let t = service.get_active(&id).await?.ok_or_else(|| {
                        n0_error::anyerr!("Tunnel '{id}' not found in project {project_id}")
                    })?;
                    // Inherit endpoint from the existing tunnel.
                    let ep = t.endpoint.clone();
                    preresolved_ns = Some((node, service, t));
                    ep
                }
                (Some(endpoint_val), Some(id_val)) => {
                    let node = ListenNode::new(repo.clone()).await?;
                    let service = TunnelService::new(datum.clone(), node.clone());
                    let t = service.get_active(&id_val).await?.ok_or_else(|| {
                        n0_error::anyerr!("Tunnel '{id_val}' not found in project {project_id}")
                    })?;
                    if t.endpoint != endpoint_val {
                        return Err(n0_error::anyerr!(
                            "--id '{id_val}' references endpoint '{}' but --endpoint was '{endpoint_val}' — they must agree (or omit --endpoint to inherit from the tunnel)",
                            t.endpoint
                        ));
                    }
                    preresolved_ns = Some((node, service, t));
                    endpoint_val
                }
                (None, None) => {
                    // Picker codepath needs a service to call list_active.
                    let node = ListenNode::new(repo.clone()).await?;
                    let service = TunnelService::new(datum.clone(), node.clone());
                    let tunnels = service.list_active().await?;
                    if tunnels.is_empty() {
                        return Err(n0_error::anyerr!(
                            "No tunnels exist in project {project_id}. Pass --endpoint to create one."
                        ));
                    }
                    let picked = if tunnels.len() == 1 {
                        // Auto-adopt the only candidate without popping a picker
                        // (informed by datum-cloud/app@cff37e7).
                        tunnels.into_iter().next().unwrap()
                    } else {
                        // Multiple candidates: silence tracing, prompt with inquire,
                        // restore tracing. inquire is sync, so call from a
                        // blocking task to keep the tokio runtime healthy.
                        let prev_filter = current_filter_string();
                        silence_tracing();
                        let choices: Vec<String> = tunnels
                            .iter()
                            .map(|t| format!("{}  ({})  → {}", t.label, t.id, t.endpoint))
                            .collect();
                        let chosen_idx_res = tokio::task::spawn_blocking(move || {
                            inquire::Select::new("Select a tunnel:", choices)
                                .with_starting_cursor(0)
                                .raw_prompt()
                                .map(|item| item.index)
                        })
                        .await
                        .map_err(|e| n0_error::anyerr!("picker task join failed: {e}"))?;
                        restore_tracing(&prev_filter);
                        let idx = chosen_idx_res
                            .map_err(|e| n0_error::anyerr!("picker error: {e}"))?;
                        tunnels.into_iter().nth(idx).unwrap()
                    };
                    let ep = picked.endpoint.clone();
                    preresolved_ns = Some((node, service, picked));
                    ep
                }
            };

            // Reuse the (node, service, existing-tunnel) tuple if one of the
            // resolution branches above already built it; otherwise build now
            // and look up the existing tunnel by endpoint.
            let (node, service, existing) = match preresolved_ns {
                Some((n, s, t)) => (n, s, Some(t)),
                None => {
                    let n = ListenNode::new(repo.clone()).await?;
                    let s = TunnelService::new(datum.clone(), n.clone());
                    let existing = s.get_active_by_endpoint(&endpoint).await?;
                    (n, s, existing)
                }
            };
            let endpoint_id = node.endpoint_id();
            let _ = writeln!(std::io::stderr(), "Your endpoint ID: {}", endpoint_id.to_string());
            let _ = writeln!(std::io::stderr(), "Setting up tunnel...");
            let _ = std::io::stderr().flush();

            let setup_start = std::time::Instant::now();
            let step_started_at = std::cell::RefCell::new(
                std::collections::HashMap::<
                    connect_lib::ProgressStepKind,
                    std::time::Instant,
                >::new(),
            );

            let tunnel_id = if let Some(t) = existing {
                if let Some(label) = label.filter(|l| l != &t.label) {
                    let updated = service.update_active(&t.id, &label, &endpoint).await?;
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({"type": "tunnel_updated", "id": updated.id})
                        );
                    }
                    updated.id
                } else {
                    t.id
                }
            } else {
                let label = label.unwrap_or_else(|| endpoint.clone());
                let tunnel = service.create_active(&label, &endpoint).await?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"type": "tunnel_created", "id": tunnel.id})
                    );
                }
                tunnel.id
            };

            let heartbeat = HeartbeatAgent::new(datum.clone(), node.clone());
            heartbeat.start().await;
            heartbeat.register_project(&project_id).await;

            service.set_enabled_active(&tunnel_id, true).await?;

            // Plan 12-03: drive setup through await_tunnel_progress (per-step
            // observability + terminal-failure short-circuit) followed by
            // verify_endpoints (probe origin + proxy URL before declaring ready).
            // The proxy probe retries indefinitely with periodic status every 10s.
            // Mode (Text/Json) routes callback output:
            //   Text → stderr (one transition line per change, prefixed by resource)
            //   Json → stdout (one tunnel_progress / tunnel_verifying /
            //                  tunnel_verified event per transition)
            // The Go supervisor's 'default: skip' case in connect/tunnel/listen/main.go
            // ignores the new event types; only the final tunnel_ready event
            // unblocks its gotReady handshake.
            let mode = if json { progress::Mode::Json } else { progress::Mode::Text };
            let progress_cb = |step: &connect_lib::ProgressStep,
                                prev: connect_lib::StepStatus| {
                let elapsed = {
                    let mut map = step_started_at.borrow_mut();
                    let timer = map
                        .entry(step.kind.clone())
                        .or_insert_with(std::time::Instant::now);
                    timer.elapsed()
                };
                progress::render_progress_step(mode, step, prev, elapsed);
            };
            let final_progress =
                progress::await_tunnel_progress(&service, &tunnel_id, &progress_cb).await?;
            let hostname = final_progress
                .hostnames
                .first()
                .cloned()
                .ok_or_else(|| {
                    n0_error::anyerr!("Tunnel {tunnel_id} has no hostname after Ready")
                })?;

            // Verify endpoints reachable. Budget is only used for the origin
            // probe (best-effort, non-fatal). The proxy probe retries
            // indefinitely with periodic status every 10s.
            let setup_elapsed = setup_start.elapsed();
            let total_budget = std::time::Duration::from_secs(60);
            let min_budget = std::time::Duration::from_secs(5);
            let verify_budget = std::cmp::max(
                total_budget.saturating_sub(setup_elapsed),
                min_budget,
            );
            let _ = writeln!(std::io::stderr(), "Verifying connectivity...");
            let _ = std::io::stderr().flush();
            let verify_cb = |label: &str, url: &str, elapsed: std::time::Duration, status: Option<u16>| {
                progress::render_verify(mode, label, url, elapsed, status);
            };
            progress::verify_endpoints(&endpoint, &hostname, verify_budget, &verify_cb).await?;

            // Re-fetch the up-to-date TunnelSummary for the tunnel_ready
            // payload (existing contract — id, label, endpoint, hostnames,
            // endpoint_id, status, elapsed_secs).
            let tunnel = service
                .get_active(&tunnel_id)
                .await?
                .ok_or_else(|| n0_error::anyerr!("Tunnel {tunnel_id} not found after setup"))?;

            let elapsed = setup_start.elapsed().as_secs();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "tunnel_ready",
                        "id": tunnel.id,
                        "label": tunnel.label,
                        "endpoint": tunnel.endpoint,
                        "hostnames": tunnel.hostnames,
                        "endpoint_id": endpoint_id.to_string(),
                        "status": "ready",
                        "elapsed_secs": elapsed
                    })
                );
            } else {
                for hostname in &tunnel.hostnames {
                    println!("Tunnel ready after {} sec: https://{}", elapsed, hostname);
                }
            }

            // --- Mid-session watch loop (Plan 12-04) ---
            // After tunnel_ready, watch three signals concurrently:
            //   1. ctrl_c        — user-initiated clean shutdown (exit 0)
            //   2. login_state   — credential expiry/revocation guidance
            //                      (text or JSON; does NOT exit so user can read)
            //   3. 10s poll      — detect mid-session terminal failure
            //                      (e.g. iroh-DNS collision flips post-Ready)
            //                      or upstream deletion (HTTPProxy removed)
            //
            // Cleanup (set_enabled_active false + tunnel_disabled) runs for
            // ALL exit paths via the post-loop block. Informed by upstream
            // datum-cloud/app@6264818 (runtime select-loop precedent).
            let mut login_rx = datum.login_state_watch();
            let mut runtime_poll =
                tokio::time::interval(std::time::Duration::from_secs(10));
            // First tick fires immediately; consume it so the first real poll
            // happens 10s after tunnel_ready (not concurrently with it).
            runtime_poll.tick().await;

            let exit_reason: ExitReason = loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        break ExitReason::CtrlC;
                    }
                    res = login_rx.changed() => {
                        if res.is_err() {
                            // Sender dropped — treat as a transient error, continue.
                            continue;
                        }
                        let state = login_rx.borrow().clone();
                        if state == connect_lib::LoginState::Missing {
                            let guidance =
                                "Datum login has expired or been revoked. \
                                 Stop this command and run `datum login` to refresh credentials. \
                                 The tunnel will continue running on cached credentials until they expire.";
                            if json {
                                println!(
                                    "{}",
                                    serde_json::json!({
                                        "type": "tunnel_login_lost",
                                        "id": tunnel_id,
                                        "message": guidance
                                    })
                                );
                            } else {
                                eprintln!("{}", guidance);
                            }
                            // Do NOT break — keep the tunnel running so the user has time to read.
                        }
                    }
                    _ = runtime_poll.tick() => {
                        match service.get_active_progress(&tunnel_id).await {
                            Ok(Some(progress)) => {
                                if let Some(failed) = progress.terminal_failure() {
                                    let msg = progress::format_terminal_failure(failed);
                                    if json {
                                        println!(
                                            "{}",
                                            serde_json::json!({
                                                "type": "tunnel_terminal_failure",
                                                "id": tunnel_id,
                                                "message": msg
                                            })
                                        );
                                    } else {
                                        eprintln!("{}", msg);
                                    }
                                    break ExitReason::TerminalFailure;
                                }
                            }
                            Ok(None) => {
                                let msg = format!(
                                    "Tunnel {tunnel_id} no longer exists on the server"
                                );
                                if json {
                                    println!(
                                        "{}",
                                        serde_json::json!({
                                            "type": "tunnel_deleted_upstream",
                                            "id": tunnel_id,
                                            "message": &msg
                                        })
                                    );
                                } else {
                                    eprintln!("{}", msg);
                                }
                                break ExitReason::DeletedUpstream;
                            }
                            Err(e) => {
                                tracing::warn!("transient progress query error: {e}");
                            }
                        }
                    }
                }
            };

            // --- Cleanup (runs for all exit paths) ---
            if let Err(e) = service.set_enabled_active(&tunnel_id, false).await {
                tracing::warn!("failed to disable tunnel on shutdown: {e}");
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({"type": "tunnel_disabled", "id": tunnel_id})
                );
            }

            // Non-zero exit for terminal failures.
            return match exit_reason {
                ExitReason::CtrlC => Ok(()),
                ExitReason::TerminalFailure => {
                    Err(n0_error::anyerr!("tunnel exited with terminal failure"))
                }
                ExitReason::DeletedUpstream => {
                    Err(n0_error::anyerr!("tunnel deleted upstream"))
                }
            };
        }
        Commands::Update { id, label, endpoint } => {
            let node = ListenNode::new(repo.clone()).await?;
            let service = TunnelService::new(datum.clone(), node.clone());
            let current = service
                .get_active(&id)
                .await?
                .ok_or_else(|| n0_error::anyerr!("Tunnel {} not found", id))?;
            let new_label = label.unwrap_or(current.label);
            let new_endpoint = endpoint.unwrap_or(current.endpoint);
            let tunnel = service.update_active(&id, &new_label, &new_endpoint).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "tunnel_updated",
                        "id": tunnel.id,
                        "label": tunnel.label,
                        "endpoint": tunnel.endpoint,
                        "hostnames": tunnel.hostnames
                    })
                );
            } else {
                println!("Updated tunnel {}:", tunnel.id);
                println!("  label: {}", tunnel.label);
                println!("  endpoint: {}", tunnel.endpoint);
            }
        }
        Commands::Delete { id } => {
            let node = ListenNode::new(repo.clone()).await?;
            let service = TunnelService::new(datum.clone(), node.clone());
            service.delete_active(&id).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"type": "tunnel_deleted", "id": id, "deleted": true})
                );
            } else {
                println!("Deleted tunnel {}", id);
            }
        }
    }
    Ok(())
}
