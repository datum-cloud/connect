pub mod config;
pub mod datum_apis;
pub mod datum_cloud;
pub mod http_user_agent;
pub mod repo;
pub mod state;

// Business logic modules — populated in Wave 2
pub mod datum_cloud_client;
pub mod project_control_plane;
pub mod tunnels;

// Node and heartbeat — populated in Wave 3
pub mod node;
pub mod heartbeat;

pub use config::{Config, DiscoveryMode};
pub use datum_cloud::external_token_source::{ExternalTokenError, ExternalTokenSource};
pub use datum_cloud::env::ApiEnv;
pub use http_user_agent::datum_http_user_agent;
pub use project_control_plane::ProjectControlPlaneClient;
pub use repo::Repo;
pub use state::{SelectedContext, State, StateWrapper};
pub use tunnels::{TunnelDeleteOutcome, TunnelService, TunnelSummary};

/// The root domain for datum connect URLs to subdomain from. A proxy URL will
/// be a three-word-codename subdomain off this URL. eg: "https://vast-gold-mine.iroh.datum.net"
pub const DATUM_CONNECT_GATEWAY_DOMAIN_NAME: &str = "iroh.datum.net";
