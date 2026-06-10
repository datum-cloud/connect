//! Binary-only tunnel progress rendering. The lib is println!-free; all
//! presentation logic lives here.
//!
//! Three responsibilities:
//! * `format_terminal_failure` — humanises a failed `ProgressStep` into an
//!   actionable, multi-line error message. The canonical case is the iroh-DNS
//!   owner-collision (`IrohDnsPublished: Pending` with `DeferredToOwner`).
//! * `render_progress_step` / `render_verify` — mode-aware callbacks that emit
//!   text-mode log lines on stderr or JSON event objects on stdout.
//! * `await_tunnel_progress` / `verify_endpoints` — async drivers that own the
//!   polling loop and HTTP probes, invoking the callbacks above on transitions.
//!
//! Mode-routing rule:
//!  - `Mode::Text` writes to stderr (so stdout stays clean for shell composition)
//!  - `Mode::Json` writes JSON event objects to stdout (so the Go supervisor's
//!    line-oriented stdin reader sees one event per line)
//!
//! # JSON EVENT CONTRACT (emitted by this module)
//!
//! | Event type           | When                          | Fields                                                          |
//! |----------------------|-------------------------------|-----------------------------------------------------------------|
//! | `tunnel_progress`    | per step status transition    | `step` (snake_case kind), `status`, `resource` (Option<String>) |
//! | `tunnel_verifying`   | start of HTTP probe per URL   | `url`                                                           |
//! | `tunnel_verified`    | HTTP probe success per URL    | `url`                                                           |
//!
//! All events go to stdout (one JSON object per line) when `Mode::Json` is
//! selected. In `Mode::Text`, transitions are printed to stderr in human form.
//! The Go supervisor (`connect/tunnel/listen/main.go`) acknowledges all three
//! types via explicit case arms but currently no-ops them — only
//! `tunnel_ready` (emitted from main.rs) drives `gotReady`.

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Set to true once the first progress step has been rendered, so the
/// test harness can detect that setup-phase output was emitted.
pub static PROGRESS_SEEN: AtomicBool = AtomicBool::new(false);

use connect_lib::{ProgressStep, ProgressStepKind, StepStatus, TunnelProgress, TunnelService};
use n0_error::Result;
use tokio::time::{sleep, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Text,
    Json,
}

// --- format_terminal_failure ---

pub fn format_terminal_failure(step: &ProgressStep) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Tunnel setup failed at step: {} ({})\n",
        step.kind.label(),
        step.kind.resource_kind()
    ));
    out.push_str(&format!(
        "  resource: {}\n",
        step.resource.as_deref().unwrap_or("(none)")
    ));
    if let Some(r) = &step.reason {
        out.push_str(&format!("  reason: {}\n", r));
    }
    if let Some(m) = &step.message {
        out.push_str(&format!("  message: {}\n", m));
    }
    if matches!(step.kind, ProgressStepKind::IrohDnsPublished)
        && step.status == StepStatus::Pending
        && step.reason.as_deref() == Some("DeferredToOwner")
    {
        out.push_str(
            "\nAnother connector with the same iroh key owns the DNS record \
             for this tunnel. Most likely this means you are running two \
             connectors against the same listen_key store. Stop the other \
             connector or use a different repo directory.\n",
        );
    }
    out
}

// --- step-name + status-name helpers (used by JSON callback) ---

pub(crate) fn step_kind_to_str(k: ProgressStepKind) -> &'static str {
    match k {
        ProgressStepKind::ProxyAccepted => "proxy_accepted",
        ProgressStepKind::CertificatesReady => "certificates_ready",
        ProgressStepKind::ConnectorReady => "connector_ready",
        ProgressStepKind::IrohDnsPublished => "iroh_dns_published",
        ProgressStepKind::ProxyProgrammed => "proxy_programmed",
        ProgressStepKind::ConnectorMetadataProgrammed => "connector_metadata_programmed",
    }
}

pub(crate) fn status_to_str(s: StepStatus) -> &'static str {
    match s {
        StepStatus::Unknown => "unknown",
        StepStatus::Pending => "pending",
        StepStatus::Ready => "ready",
    }
}

// --- callbacks ---

pub fn render_progress_step(mode: Mode, step: &ProgressStep, _prev: StepStatus, elapsed: Duration) {
    if step.status == StepStatus::Ready {
        let _ = writeln!(
            std::io::stderr(),
            "  \u{2713} {} ({:.1}s) [{}]",
            step.kind.label(),
            elapsed.as_secs_f64(),
            step.resource.as_deref().unwrap_or(""),
        );
        let _ = std::io::stderr().flush();
    }
    if mode == Mode::Json {
        let v = serde_json::json!({
            "type": "tunnel_progress",
            "step": step_kind_to_str(step.kind),
            "status": status_to_str(step.status),
            "resource": step.resource,
        });
        println!("{}", v);
    }
}

pub fn render_verify(mode: Mode, label: &str, url: &str, elapsed: Duration, status: Option<u16>) {
    let status_str = match status {
        Some(s) => format!(": HTTP {}", s),
        None => String::new(),
    };
    let _ = writeln!(
        std::io::stderr(),
        "  \u{2713} {} ({:.1}s) [{}]{}",
        label,
        elapsed.as_secs_f64(),
        url,
        status_str,
    );
    let _ = std::io::stderr().flush();
    if mode == Mode::Json {
        let json_type = match status {
            Some(_) => "tunnel_verified",
            None => "tunnel_verifying",
        };
        println!(
            "{}",
            serde_json::json!({ "type": json_type, "url": url })
        );
    }
}

// --- URL builder for verify_endpoints ---

pub fn build_probe_urls(endpoint: &str, hostname: &str) -> (String, String) {
    let origin = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("http://{}", endpoint)
    };
    let proxy = format!("https://{}", hostname);
    (origin, proxy)
}

// --- await_tunnel_progress ---

/// Poll `service.get_active_progress(tunnel_id)` on a 250ms cadence; emit a
/// transition callback for every step whose status changed since the previous
/// poll. Returns the final `TunnelProgress` when all steps are Ready, returns
/// an error formatted via `format_terminal_failure` when a terminal-failure
/// step is observed, and returns an error if the tunnel disappears upstream
/// during setup. Emits a one-shot stderr warning when a step has been Pending
/// for ≥ 30 seconds.
///
/// No overall timeout: the caller (Listen handler) bounds total time via the
/// 60-second Go-supervisor startup window in `connect/tunnel/listen/main.go`.
pub async fn await_tunnel_progress<F>(
    service: &TunnelService,
    tunnel_id: &str,
    progress_cb: F,
) -> Result<TunnelProgress>
where
    F: Fn(&ProgressStep, StepStatus),
{
    let mut last_seen: HashMap<ProgressStepKind, StepStatus> = HashMap::new();
    let mut pending_since: HashMap<ProgressStepKind, Instant> = HashMap::new();
    let mut warned_stuck: HashMap<ProgressStepKind, bool> = HashMap::new();

    loop {
        let progress_opt = service
            .get_active_progress(tunnel_id)
            .await
            .map_err(|e| n0_error::anyerr!("polling tunnel {tunnel_id} progress: {e}"))?;
        let Some(progress) = progress_opt else {
            return Err(n0_error::anyerr!(
                "Tunnel {tunnel_id} disappeared during setup"
            ));
        };

        // Diff and emit transitions.
        for step in &progress.steps {
            let prev = last_seen
                .get(&step.kind)
                .copied()
                .unwrap_or(StepStatus::Unknown);
            if prev != step.status {
                progress_cb(step, prev);
                last_seen.insert(step.kind, step.status);
            }
            // Track Pending duration; emit a one-shot stuck warning at 30s.
            if step.status == StepStatus::Pending {
                pending_since.entry(step.kind).or_insert_with(Instant::now);
                if let Some(start) = pending_since.get(&step.kind) {
                    let secs = start.elapsed().as_secs();
                    if secs >= 30 && !warned_stuck.get(&step.kind).copied().unwrap_or(false) {
                        let _ = writeln!(
                            std::io::stderr(),
                            "warning: step {} stuck in Pending for {}s ({})",
                            step.kind.label(),
                            secs,
                            step.resource.as_deref().unwrap_or("(no resource)")
                        );
                        let _ = std::io::stderr().flush();
                        warned_stuck.insert(step.kind, true);
                    }
                }
            } else {
                pending_since.remove(&step.kind);
                warned_stuck.remove(&step.kind);
            }
        }

        // Check terminal failure.
        if let Some(failed) = progress.terminal_failure() {
            return Err(n0_error::anyerr!("{}", format_terminal_failure(failed)));
        }

        if progress.all_ready() {
            return Ok(progress);
        }

        sleep(Duration::from_millis(250)).await;
    }
}

// --- verify_endpoints ---

/// Probe the origin endpoint (HTTP, best-effort) and proxy URL (HTTPS,
/// indefinite). Origin is bounded by `budget` and is non-fatal on failure.
/// Proxy retries indefinitely with exponential backoff and prints a status
/// message every 10s (e.g. `"  waiting for proxy [url] (30s) ... HTTP 503"`)
/// so the user sees progress even during long settling times.
pub async fn verify_endpoints<F>(
    origin_endpoint: &str,
    hostname: &str,
    budget: Duration,
    verify_cb: F,
) -> Result<()>
where
    F: Fn(&str, &str, Duration, Option<u16>),
{
    let (origin_url, proxy_url) = build_probe_urls(origin_endpoint, hostname);

    let per_attempt_timeout = Duration::from_secs(5);
    let client = reqwest::Client::builder()
        .timeout(per_attempt_timeout)
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| n0_error::anyerr!("building reqwest client for verify_endpoints: {e}"))?;

    // Origin probe — best-effort with budget, non-fatal on failure.
    match probe_until_reachable(&client, &origin_url, budget / 2).await {
        Ok((elapsed, status)) => {
            verify_cb("origin reachable", &origin_url, elapsed, Some(status));
        }
        Err(_e) => {
            let _ = writeln!(
                std::io::stderr(),
                "warning: origin {} did not respond within budget — continuing",
                origin_url
            );
            let _ = std::io::stderr().flush();
        }
    }

    // Proxy probe — indefinite retry with periodic status every 10s.
    let start = Instant::now();
    let mut backoff = Duration::from_millis(250);
    let mut last_status = Instant::now();
    loop {
        match client.get(&proxy_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status < 500 {
                    verify_cb("proxy responding", &proxy_url, start.elapsed(), Some(status));
                    return Ok(());
                }
                if last_status.elapsed() >= Duration::from_secs(10) {
                    let _ = writeln!(
                        std::io::stderr(),
                        "  waiting for proxy [{}] ({:.0}s) ... HTTP {}",
                        proxy_url,
                        start.elapsed().as_secs_f64(),
                        status,
                    );
                    let _ = std::io::stderr().flush();
                    last_status = Instant::now();
                }
            }
            Err(_e) => {
                if last_status.elapsed() >= Duration::from_secs(10) {
                    let _ = writeln!(
                        std::io::stderr(),
                        "  waiting for proxy [{}] ({:.0}s) ... no response",
                        proxy_url,
                        start.elapsed().as_secs_f64(),
                    );
                    let _ = std::io::stderr().flush();
                    last_status = Instant::now();
                }
            }
        }
        let sleep_dur = std::cmp::min(backoff, Duration::from_secs(2));
        sleep(sleep_dur).await;
        backoff = std::cmp::min(backoff * 2, Duration::from_secs(2));
    }
}

async fn probe_until_reachable(
    client: &reqwest::Client,
    url: &str,
    budget: Duration,
) -> Result<(Duration, u16)> {
    let start = Instant::now();
    let mut backoff = Duration::from_millis(250);
    loop {
        if start.elapsed() >= budget {
            return Err(n0_error::anyerr!("probe budget exhausted"));
        }
        match client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status < 500 {
                    return Ok((start.elapsed(), status));
                }
            }
            Err(_e) => {}
        }
        let remaining = budget.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(n0_error::anyerr!("probe budget exhausted"));
        }
        sleep(std::cmp::min(backoff, remaining)).await;
        backoff = std::cmp::min(backoff * 2, Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(kind: ProgressStepKind, status: StepStatus, reason: Option<&str>) -> ProgressStep {
        ProgressStep {
            kind,
            status,
            reason: reason.map(String::from),
            message: None,
            resource: Some(format!("{}/x", kind.resource_kind())),
        }
    }

    #[test]
    fn terminal_failure_iroh_owner_collision_includes_actionable_message() {
        let s = step(
            ProgressStepKind::IrohDnsPublished,
            StepStatus::Pending,
            Some("DeferredToOwner"),
        );
        let out = format_terminal_failure(&s);
        assert!(out.contains("Tunnel setup failed at step"));
        assert!(out.contains("Another connector with the same iroh key"));
    }

    #[test]
    fn terminal_failure_generic_still_has_header_and_resource() {
        let s = step(
            ProgressStepKind::ProxyAccepted,
            StepStatus::Pending,
            Some("Whatever"),
        );
        let out = format_terminal_failure(&s);
        assert!(out.contains("Tunnel setup failed at step"));
        assert!(out.contains("resource: HTTPProxy/x"));
        assert!(!out.contains("Another connector with the same iroh key"));
    }

    #[test]
    fn build_probe_urls_adds_http_prefix_to_bare_endpoint() {
        let (origin, proxy) = build_probe_urls("localhost:8080", "x.example.com");
        assert_eq!(origin, "http://localhost:8080");
        assert_eq!(proxy, "https://x.example.com");
    }

    #[test]
    fn build_probe_urls_keeps_scheme_when_present() {
        let (origin, _) = build_probe_urls("https://api.example.com", "x.example.com");
        assert_eq!(origin, "https://api.example.com");
    }

    #[test]
    fn json_progress_event_parses_back_to_expected_fields() {
        // We can't directly capture println output in a unit test trivially;
        // instead, reconstruct the same json! body and re-parse.
        let s = step(ProgressStepKind::ProxyAccepted, StepStatus::Ready, None);
        let v = serde_json::json!({
            "type": "tunnel_progress",
            "step": step_kind_to_str(s.kind),
            "status": status_to_str(s.status),
            "resource": s.resource,
        });
        let parsed: serde_json::Value = serde_json::from_str(&v.to_string()).unwrap();
        assert_eq!(parsed["type"], "tunnel_progress");
        assert_eq!(parsed["step"], "proxy_accepted");
        assert_eq!(parsed["status"], "ready");
        assert!(parsed["resource"].is_string());
    }
}
