//! Binary-only tunnel progress rendering. The lib is println!-free; all
//! presentation logic lives here.
//!
//! Three responsibilities:
//! * `format_terminal_failure` — humanises a failed `ProgressStep` into an
//!   actionable, multi-line error message. The canonical case is the iroh-DNS
//!   owner-collision (`IrohDnsPublished: Pending` with `DeferredToOwner`).
//! * `render_progress_step` / `render_verify` — mode-aware callbacks that emit
//!   text-mode log lines on stderr or JSON event objects on stdout.
//! * `await_tunnel_progress` / `verify_endpoints` — async drivers (implemented
//!   in Task 3 of plan 12-03) that own the polling loop and HTTP probes,
//!   invoking the callbacks above on transitions.
//!
//! Mode-routing rule:
//!  - `Mode::Text` writes to stderr (so stdout stays clean for shell composition)
//!  - `Mode::Json` writes JSON event objects to stdout (so the Go supervisor's
//!    line-oriented stdin reader sees one event per line)

use connect_lib::{ProgressStep, ProgressStepKind, StepStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyEvent {
    Verifying,
    Verified,
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

pub fn render_progress_step(mode: Mode, step: &ProgressStep, prev: StepStatus) {
    match mode {
        Mode::Text => {
            eprintln!(
                "[{}] {}: {} -> {}",
                step.kind.resource_kind(),
                step.kind.label(),
                status_to_str(prev),
                status_to_str(step.status),
            );
        }
        Mode::Json => {
            let v = serde_json::json!({
                "type": "tunnel_progress",
                "step": step_kind_to_str(step.kind),
                "status": status_to_str(step.status),
                "resource": step.resource,
            });
            println!("{}", v);
        }
    }
}

pub fn render_verify(mode: Mode, url: &str, event: VerifyEvent) {
    let (text_prefix, json_type) = match event {
        VerifyEvent::Verifying => ("verifying", "tunnel_verifying"),
        VerifyEvent::Verified => ("verified", "tunnel_verified"),
    };
    match mode {
        Mode::Text => eprintln!("{} {}", text_prefix, url),
        Mode::Json => println!(
            "{}",
            serde_json::json!({ "type": json_type, "url": url })
        ),
    }
}

// (await_tunnel_progress and verify_endpoints implemented in Task 3 of this plan.)

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
