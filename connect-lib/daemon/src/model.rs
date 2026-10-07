use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    pub version: u32,
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectState>,
    #[serde(default)]
    pub tokens: Vec<TokenRecord>,
    #[serde(default)]
    pub audit: Vec<AuditEntry>,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            projects: BTreeMap::new(),
            tokens: Vec::new(),
            audit: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectState {
    /// Saved peer approvals, not an instruction to reconnect after restart.
    #[cfg(feature = "networking")]
    #[serde(default)]
    pub peer_networks: BTreeMap<String, crate::peer_ip::Binding>,
    /// Controller-managed VPC attachments that should be recreated whenever
    /// this project is running. The privileged helper remains the authority
    /// for the exact address and routes; this intent never expands approval.
    #[cfg(feature = "networking")]
    #[serde(default)]
    pub managed_networks: BTreeMap<String, ManagedNetworkState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub desired_up: bool,
    #[serde(default)]
    pub running: bool,
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector: Option<ConnectorState>,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceState>,
    #[serde(default)]
    pub dials: BTreeMap<u16, DialState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_stage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedNetworkState {
    pub network: String,
    pub desired_attached: bool,
    #[serde(default)]
    pub running: bool,
    #[serde(default = "inactive_network_state")]
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_stage: Option<String>,
    pub last_actor: String,
}

fn inactive_network_state() -> String {
    "inactive".into()
}

/// Non-secret authentication provenance for status and restart diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorState {
    pub name: String,
    pub uid: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceState {
    pub id: String,
    pub endpoint: String,
    #[serde(default)]
    pub protocol: Protocol,
    pub public: bool,
    pub hostname: Option<String>,
    pub allow: Vec<String>,
    pub desired_active: bool,
    #[serde(default)]
    pub running: bool,
    pub ready: bool,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_stage: Option<String>,
    pub last_actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialState {
    pub connector: String,
    /// Display-only name. Authorization always uses the pinned connector key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,
    pub port: u16,
    /// Requested loopback port. Zero asks the OS for an ephemeral port.
    pub bind: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
    #[serde(default)]
    pub protocol: Protocol,
    pub desired_active: bool,
    #[serde(default)]
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_stage: Option<String>,
    pub last_actor: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Setup,
    Operate,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub role: Role,
    pub salt: String,
    pub secret_hash: String,
    pub project: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts_unix_ms: i64,
    pub event: String,
    pub project: Option<String>,
    pub resource: Option<String>,
    pub actor: String,
}

pub fn append_audit(state: &mut DaemonState, entry: AuditEntry) {
    const MAX_AUDIT: usize = 500;
    state.audit.push(entry);
    if state.audit.len() > MAX_AUDIT {
        state.audit.drain(..state.audit.len() - MAX_AUDIT);
    }
}
